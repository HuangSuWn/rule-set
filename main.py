import configparser
import os
import json
import logging
import subprocess
import time
import yaml
import re
import concurrent.futures
import requests
import pandas as pd
from utils import *
from config import Config
from collections import defaultdict
import tempfile
import shutil

config = Config()


class RuleParser:
    def __init__(self):
        self.ls_index = 1

    def parse_adguard_file(self, yaml_file_path, output_directory):
        try:
            with open(yaml_file_path, 'r') as file:
                data = yaml.safe_load(file)
                logging.debug(f"解析的 YAML 数据: {data}")

            rule_set_name = os.path.basename(yaml_file_path).split('.')[0]
            adg_links = data.get('adguard', [])
            unique_lines = set()

            for link in adg_links:
                try:
                    response = requests.get(link)
                    response.raise_for_status()
                    raw_data = response.text
                    lines = raw_data.splitlines()
                    for line in lines:
                        if line.strip():
                            unique_lines.add(line.strip())
                except requests.RequestException as e:
                    logging.error(f"获取链接 {link} 时出错: {e}")

            tmp_dir = tempfile.mkdtemp()
            logging.debug(f"创建临时目录: {tmp_dir}")
            adguard_file_path = os.path.join(tmp_dir, "adguard_combined.txt")

            with open(adguard_file_path, "w") as f:
                f.write("\n".join(sorted(unique_lines)))

            srs_file_path = os.path.join(output_directory, "{}.srs".format(rule_set_name))
            conversion_command = [
                "sing-box", "rule-set", "convert", "--type", "adguard",
                "--output", srs_file_path, adguard_file_path
            ]
            logging.debug(f"执行转换命令: {' '.join(conversion_command)}")

            result = subprocess.run(conversion_command, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"转换命令失败，错误信息: {result.stderr}")
                return None

            if not os.path.exists(srs_file_path):
                logging.error(f"转换失败，没有找到生成的 SRS 文件: {srs_file_path}")
                return None

            os.remove(adguard_file_path)
            os.rmdir(tmp_dir)

        except Exception as e:
            logging.error(f"处理 AdGuard 文件时出错: {e}")
            return None

    def parse_littlesnitch_file(self, link, retries=3, delay=5):
        try:
            logging.debug(f"正在处理 Little Snitch 链接: {link}")

            for attempt in range(retries):
                try:
                    response = requests.get(link)
                    response.raise_for_status()
                    break
                except requests.exceptions.RequestException as e:
                    logging.error(f"请求失败: {e}")
                    if attempt < retries - 1:
                        time.sleep(delay)
                    else:
                        logging.error(f"已达到最大重试次数 ({retries})，停止请求。")
                        return None

            raw_data = response.text
            cleaned_raw_data = clean_json_data(raw_data)
            data = json.loads(cleaned_raw_data)
            denied_domains = data.get("denied-remote-domains", [])
            cleaned_denied_domains = clean_denied_domains(denied_domains)

            if not (cleaned_denied_domains["domain"] or cleaned_denied_domains["domain_suffix"]):
                logging.warning(f"从 {link} 未找到 'denied-remote-domains' 数据")
                return None

            output_data = {
                "rules": [
                    {
                        "domain": cleaned_denied_domains["domain"],
                        "domain_suffix": cleaned_denied_domains["domain_suffix"]
                    }
                ],
                "version": 4
            }
            return output_data

        except Exception as e:
            logging.error(f"处理链接 {link} 时发生错误：{e}")
            return None

    def parse_yaml_file(self, yaml_file, output_directory):
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)

        geosite_links = data.get('geosite', [])
        geoip_links = data.get('geoip', [])
        process_links = data.get('process', [])
        geositeip_links = data.get('geositeip', [])

        rule_set_name = os.path.basename(yaml_file).split('.')[0]

        geosite_file = os.path.join(output_directory, f"geosite-{rule_set_name}.json")
        geoip_file = os.path.join(output_directory, f"geoip-{rule_set_name}.json")
        process_file = os.path.join(output_directory, f"process-{rule_set_name}.json")
        geositeip_file = os.path.join(output_directory, f"geositeip-{rule_set_name}.json")

        final_results = []

        if geosite_links:
            geosite_result = self.generate_json_file(geosite_links, geosite_file, rule_set_name)
            final_results.append(("geosite", geosite_result))

        if geoip_links:
            geoip_result = self.generate_json_file(geoip_links, geoip_file, rule_set_name)
            final_results.append(("geoip", geoip_result))

        if process_links:
            process_result = self.generate_json_file(process_links, process_file, rule_set_name)
            final_results.append(("process", process_result))

        if geositeip_links:
            geositeip_result = self.generate_json_file(geositeip_links, geositeip_file, rule_set_name)
            final_results.append(("geositeip", geositeip_result))

        logging.info(f"{rule_set_name} 规则整理完成:")
        for result_type, result_data in final_results:
            logging.info(
                f"类型: {result_type}\n"
                f"domain 被过滤掉的条目数量: {result_data['filtered_count']}\n"
                f"剩余规则总数: {result_data['total_rules']}\n"
                f"规则分析:\n"
                f"  domain 条目数: {result_data['domain_count']}\n"
                f"  domain_suffix 条目数: {result_data['domain_suffix_count']}\n"
                f"  ip_cidr 条目数: {result_data['ip_cidr_count']}\n"
                f"  process_name 条目数: {result_data['process_name_count']}\n"
                f"  domain_regex 条目数: {result_data['domain_regex_count']}\n"
                f"{'-'*50}"
            )

    def download_srs_file(self, url):
        try:
            tmp_dir = tempfile.mkdtemp()
            srs_file_path = os.path.join(tmp_dir, os.path.basename(url))
            response = requests.get(url)
            response.raise_for_status()
            with open(srs_file_path, 'wb') as file:
                file.write(response.content)
            return srs_file_path
        except Exception as e:
            logging.error(f"下载 {url} 时出错: {e}")
            return None

    def download_and_parse_json(self, json_file_url):
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
                response = requests.get(json_file_url, stream=True)
                response.raise_for_status()
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_file_path = tmp_file.name

            with open(tmp_file_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            os.remove(tmp_file_path)
            return json_data

        except Exception as e:
            logging.error(f"处理 JSON 文件失败: {json_file_url}, 错误: {e}")
            return None

    def generate_json_file(self, links, output_file, rule_set_name):
        unique_links = list(set(links))
        json_file_list = []
        for link in unique_links:
            json_file = self.parse_link_file_to_json(link)
            json_file_list.append(json_file)

        if len(json_file_list) == 1 and config.trust_upstream:
            single_file_stats = json_file_list[0]
            final_rules = single_file_stats

            # geoip 文件移除 domain 字段
            if "geoip" in output_file:
                for rule in final_rules.get("rules", []):
                    if "domain" in rule:
                        del rule["domain"]

            domain_count = sum(len(rule.get("domain", [])) for rule in final_rules.get("rules", []))
            domain_suffix_count = sum(len(rule.get("domain_suffix", [])) for rule in final_rules.get("rules", []))
            ip_cidr_count = sum(len(rule.get("ip_cidr", [])) for rule in final_rules.get("rules", []))
            process_name_count = sum(len(rule.get("process_name", [])) for rule in final_rules.get("rules", []))
            domain_regex_count = sum(len(rule.get("domain_regex", [])) for rule in final_rules.get("rules", []))

            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump(final_rules, file, ensure_ascii=False, indent=4)

            return {
                "filtered_count": 0,
                "total_rules": len(final_rules.get("rules", [])),
                "domain_count": domain_count,
                "domain_suffix_count": domain_suffix_count,
                "ip_cidr_count": ip_cidr_count,
                "process_name_count": process_name_count,
                "domain_regex_count": domain_regex_count
            }
        else:
            return self.merge_json(json_file_list, output_file, rule_set_name=rule_set_name)

    def merge_json(self, json_file_list, output_file, rule_set_name,
                   enable_trie_filtering=config.enable_trie_filtering):
        merged_rules = {
            "process_name": set(),
            "domain": set(),
            "domain_suffix": set(),
            "ip_cidr": set(),
            "domain_regex": set()
        }

        for json_file in json_file_list:
            try:
                for rule in json_file.get("rules", []):
                    if isinstance(rule, dict):
                        for category, values in rule.items():
                            if category in merged_rules and values:
                                if isinstance(values, list):
                                    merged_rules[category].update(values)
                                elif isinstance(values, str):
                                    merged_rules[category].add(values)
            except Exception as e:
                logging.error(f"解析 JSON 数据时出错: {e}")

        filtered_count = 0
        final_domains = merged_rules.get("domain", set())
        if enable_trie_filtering and merged_rules.get("domain_suffix"):
            if merged_rules.get("domain"):
                final_domains, filtered_count = filter_domains_with_trie(
                    merged_rules["domain"], merged_rules["domain_suffix"]
                )

        merged_rules["domain"] = final_domains

        # geoip 文件移除 domain
        if "geoip" in output_file and "domain" in merged_rules:
            del merged_rules["domain"]

        final_rules = [{category: list(values)} for category, values in merged_rules.items() if values]

        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump({"version": 4, "rules": final_rules}, file, ensure_ascii=False, indent=4)

        return {
            "filtered_count": filtered_count,
            "total_rules": sum(len(values) for values in merged_rules.values()),
            "domain_count": len(merged_rules.get("domain", [])),
            "domain_suffix_count": len(merged_rules.get("domain_suffix", [])),
            "ip_cidr_count": len(merged_rules.get("ip_cidr", [])),
            "process_name_count": len(merged_rules.get("process_name", [])),
            "domain_regex_count": len(merged_rules.get("domain_regex", []))
        }

    def decompile_srs_to_json(self, srs_file_url):
        try:
            srs_file = self.download_srs_file(srs_file_url)
            if not srs_file:
                logging.error(f"下载 .srs 文件失败: {srs_file_url}")
                return None

            output_json_path = srs_file.replace(".srs", ".json")
            os.system(f"sing-box rule-set decompile --output {output_json_path} {srs_file}")

            with open(output_json_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            os.remove(srs_file)
            os.remove(output_json_path)

            return json_data

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

    def parse_link_file_to_json(self, link):
        try:
            if link.endswith('.json'):
                return self.download_and_parse_json(link)
            if link.endswith('.srs'):
                return self.decompile_srs_to_json(link)
            if any(keyword in link for keyword in config.ls_keyword):
                return self.parse_littlesnitch_file(link)

            with concurrent.futures.ThreadPoolExecutor() as executor:
                results = list(executor.map(parse_and_convert_to_dataframe, [link]))
                dfs = [df for df, rules in results]
                df = pd.concat(dfs, ignore_index=True)

            df = df[~df['pattern'].str.contains('IP-CIDR6')].reset_index(drop=True)
            df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
            df = df[df['pattern'].isin(config.map_dict.keys())].reset_index(drop=True)
            df = df.drop_duplicates().reset_index(drop=True)
            df['pattern'] = df['pattern'].replace(config.map_dict)

            result_rules = {"version": 4, "rules": []}
            domain_entries = []
            for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
                if pattern == 'domain_suffix':
                    result_rules["rules"].append({pattern: [addr.strip() for addr in addresses]})
                elif pattern == 'domain':
                    domain_entries.extend([addr.strip() for addr in addresses])
                else:
                    result_rules["rules"].append({pattern: [addr.strip() for addr in addresses]})

            if domain_entries:
                result_rules["rules"].insert(0, {'domain': list(set(domain_entries))})

            return result_rules

        except Exception as e:
            logging.error(f"解析链接 {link} 出现错误: {e}")
            return None

    def process_category_files(self, directory):
        category_files = [f for f in os.listdir(directory) if "category" in f and f.endswith('.json')]
        grouped_files = defaultdict(list)
        for file in category_files:
            base_name = file.split("@")[0].replace(".json", "")
            grouped_files[base_name].append(file)

        for category, files in grouped_files.items():
            self.process_single_category(directory, category, files)

    def process_single_category(self, directory, category, files):
        general_files = [f for f in files if "@" not in f]
        non_cn_files = [f for f in files if "@!cn" in f]
        cn_files = [f for f in files if "@cn" in f]

        if not general_files:
            return

        general_file_path = os.path.join(directory, general_files[0])
        general_data = load_json(general_file_path).get("rules", [])

        if cn_files and non_cn_files:
            cn_path = os.path.join(directory, cn_files[0])
            non_cn_path = os.path.join(directory, non_cn_files[0])
            cn_data = load_json(cn_path).get("rules", [])
            updated_non_cn_data = merge_rules(load_json(non_cn_path).get("rules", []),
                                              subtract_rules(general_data, cn_data))
            final_non_cn_data = convert_sets_to_lists(deduplicate_json(updated_non_cn_data))
            final_cn_data = cn_data
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)
        elif cn_files and not non_cn_files:
            cn_path = os.path.join(directory, cn_files[0])
            cn_data = load_json(cn_path).get("rules", [])
            non_cn_data = subtract_rules(general_data, cn_data)
            non_cn_path = os.path.join(directory, f"{category}@!cn.json")
            save_json(non_cn_data, non_cn_path)
            save_json(cn_data, cn_path)
        elif non_cn_files and not cn_files:
            non_cn_path = os.path.join(directory, non_cn_files[0])
            non_cn_data = load_json(non_cn_path).get("rules", [])
            cn_data = subtract_rules(general_data, non_cn_data)
            cn_path = os.path.join(directory, f"{category}@cn.json")
            save_json(non_cn_data, non_cn_path)
            save_json(cn_data, cn_path)

        try:
            os.remove(general_file_path)
        except OSError:
            pass

    def main(self):
        source_directory = config.source_dir
        output_directory = config.singbox_output_directory

        if os.path.exists(output_directory):
            shutil.rmtree(output_directory)
        os.makedirs(output_directory)

        yaml_files = [f for f in os.listdir(source_directory) if f.endswith('.yaml')]
        for yaml_file in yaml_files:
            yaml_file_path = os.path.join(source_directory, yaml_file)
            if any(keyword in yaml_file for keyword in config.adg_keyword):
                self.parse_adguard_file(yaml_file_path, output_directory)
            else:
                self.parse_yaml_file(yaml_file_path, output_directory)

        self.process_category_files(output_directory)

        json_files = [f for f in os.listdir(output_directory) if f.endswith('.json')]
        for json_file in json_files:
            json_file_path = os.path.join(output_directory, json_file)
            srs_path = json_file_path.replace(".json", ".srs")
            os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")

        convert_json_to_surge(output_directory)
        convert_json_to_clash(output_directory)
        convert_yaml_to_mrs(config.clash_output_directory)


if __name__ == "__main__":
    rule_parser = RuleParser()
    rule_parser.main()

        # 如果只有一个 JSON 文件，直接保存，不调用 merge_json
        if len(json_file_list) == 1 and config.trust_upstream:
            single_file_stats = json_file_list[0]
            final_rules = single_file_stats

            # 统计信息
            domain_count = len(single_file_stats.get("domain", []))
            domain_suffix_count = len(single_file_stats.get("domain_suffix", []))
            ip_cidr_count = len(single_file_stats.get("ip_cidr", []))
            process_name_count = len(single_file_stats.get("process_name", []))
            domain_regex_count = len(single_file_stats.get("domain_regex", []))

            # 顶层信息
            statistics = {
                "filtered_count": 0,
                "total_rules": len(final_rules),
                "domain_count": domain_count,
                "domain_suffix_count": domain_suffix_count,
                "ip_cidr_count": ip_cidr_count,
                "process_name_count": process_name_count,
                "domain_regex_count": domain_regex_count
                }

            try:
                with open(output_file, 'w', encoding='utf-8') as file:
                    json.dump(final_rules, file, ensure_ascii=False, indent=4)
            except Exception as e:
                logging.error(f"保存 JSON 文件时出错: {e}")
                return {"error": str(e)}

            # 返回统计信息
            return statistics
        # 否则调用 merge_json
        else:
            return self.merge_json(json_file_list, output_file, rule_set_name=rule_set_name)

    def merge_json(self, json_file_list, output_file, rule_set_name,
                   enable_trie_filtering=config.enable_trie_filtering):
        """
        合并 JSON 文件并返回规则统计信息。
        """
        logging.debug(f"正在合并 JSON 文件: {json_file_list}")

        # 初始化合并规则
        merged_rules = {
            "process_name": set(),
            "domain": set(),
            "domain_suffix": set(),
            "ip_cidr": set(),
            "domain_regex": set()
        }

        # 第一轮合并与去重
        for json_file in json_file_list:
            try:
                for rule in json_file.get("rules", []):
                    if isinstance(rule, dict):
                        for category, values in rule.items():
                            if category in merged_rules and values:
                                if isinstance(values, list):
                                    merged_rules[category].update(values)
                                elif isinstance(values, str):
                                    merged_rules[category].add(values)
            except Exception as e:
                logging.error(f"解析 JSON 数据时出错: {e}")

        # 基于 domain_suffix 的 Trie 去重
        original_domain_count = len(merged_rules.get("domain", set()))
        filtered_count = 0
        final_domains = set()

        if enable_trie_filtering and merged_rules.get("domain_suffix"):
            if merged_rules.get("domain"):
                final_domains, filtered_count = filter_domains_with_trie(
                    merged_rules["domain"], merged_rules["domain_suffix"]
                )
            else:
                final_domains = merged_rules.get("domain", set())
        else:
            final_domains = merged_rules.get("domain", set())

        # 更新合并后的 domain 规则
        merged_rules["domain"] = final_domains

        # 转换为最终规则列表
        final_rules = [
            {category: list(values)}
            for category, values in merged_rules.items()
            if values
        ]

        # 保存结果
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump({"version": 4, "rules": final_rules}, file, ensure_ascii=False, indent=4)
        except Exception as e:
            logging.error(f"保存 JSON 文件时出错: {e}")

        # 返回统计信息
        return {
            "filtered_count": filtered_count,
            "total_rules": sum(len(values) for values in merged_rules.values()),
            "domain_count": len(merged_rules["domain"]),
            "domain_suffix_count": len(merged_rules["domain_suffix"]),
            "ip_cidr_count": len(merged_rules["ip_cidr"]),
            "process_name_count": len(merged_rules["process_name"]),
            "domain_regex_count": len(merged_rules["domain_regex"])
        }

    def decompile_srs_to_json(self, srs_file_url):
        """
        处理远程 .srs 文件，下载并使用 sing-box 的 decompile 命令转换为 JSON 文件。
        """
        try:
            # 下载 .srs 文件到临时目录
            srs_file = self.download_srs_file(srs_file_url)
            if not srs_file:
                logging.error(f"下载 .srs 文件失败: {srs_file_url}")
                return None

            # 解编译 SRS 文件为 JSON
            output_json_path = srs_file.replace(".srs", ".json")
            os.system(f"sing-box rule-set decompile --output {output_json_path} {srs_file}")
            # logging.info(f"成功将 SRS 文件 {srs_file} 解编译为 JSON 文件 {output_json_path}")

            # 读取解编译后的 JSON 文件并返回
            with open(output_json_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            # 清理临时文件
            os.remove(srs_file)
            os.remove(output_json_path)

            return json_data

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

    def parse_link_file_to_json(self, link):
        """
        解析给定的链接并返回处理后的 JSON 数据。
        """
        try:
            # logging.info(f"正在解析链接: {link}")

            if link.endswith('.json'):
                logging.debug(f"检测到 JSON 文件 {link}，直接返回内容")
                return self.download_and_parse_json(link)

            if link.endswith('.srs'):
                logging.debug(f"检测到 SRS 文件 {link}，正在进行解编译处理")
                json_file = self.decompile_srs_to_json(link)
                return json_file

            if any(keyword in link for keyword in config.ls_keyword):
                json_file = self.parse_littlesnitch_file(link)
                return json_file

            with concurrent.futures.ThreadPoolExecutor() as executor:
                results = list(executor.map(parse_and_convert_to_dataframe, [link]))
                dfs = [df for df, rules in results]
                rules_list = [rules for df, rules in results]
                df = pd.concat(dfs, ignore_index=True)

            logging.debug(f"生成的 DataFrame: {df.head()}")
            df = df[~df['pattern'].str.contains('IP-CIDR6')].reset_index(drop=True)
            df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
            df = df[df['pattern'].isin(config.map_dict.keys())].reset_index(drop=True)
            df = df.drop_duplicates().reset_index(drop=True)
            df['pattern'] = df['pattern'].replace(config.map_dict)

            result_rules = {"version": 4, "rules": []}
            domain_entries = []
            for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
                if pattern == 'domain_suffix':
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)
                elif pattern == 'domain':
                    domain_entries.extend([address.strip() for address in addresses])
                else:
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)

            domain_entries = list(set(domain_entries))
            if domain_entries:
                result_rules["rules"].insert(0, {'domain': domain_entries})

            logging.debug(f"生成的 JSON 数据: {result_rules}")
            return result_rules

        except Exception as e:
            logging.error(f"解析链接 {link} 出现错误: {e}")
            return None

    def process_category_files(self, directory):
        # 找到包含 category 的文件并按类别分组
        category_files = [f for f in os.listdir(directory) if "category" in f and f.endswith('.json')]
        grouped_files = defaultdict(list)

        # 按类别分组文件，例如 geoip-category-communitaion.json -> geoip-category-communitaion
        for file in category_files:
            base_name = file.split("@")[0].replace(".json", "")
            grouped_files[base_name].append(file)

        # 分别处理每一组文件
        for category, files in grouped_files.items():
            logging.info(f"处理类别：{category}")
            self.process_single_category(directory, category, files)

    def process_single_category(self, directory, category, files):
        # 分组文件
        general_files = [f for f in files if "@" not in f]
        non_cn_files = [f for f in files if "@!cn" in f]
        cn_files = [f for f in files if "@cn" in f]

        # 如果没有全体文件，跳过
        if not general_files:
            logging.info(f"跳过处理 {category}，因为没有全体文件")
            return

        # 加载全体文件
        general_file_path = os.path.join(directory, general_files[0])
        general_data = load_json(general_file_path).get("rules",[])

        # 如果同时有 @cn 和 @!cn 文件
        if cn_files and non_cn_files:
            # 优先处理非 cn 文件
            cn_path = os.path.join(directory, cn_files[0])
            non_cn_path = os.path.join(directory, non_cn_files[0])

            cn_data = load_json(cn_path).get("rules",[])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            updated_non_cn_data = subtract_rules(general_data, cn_data)

            # @!cn 文件已存在，增量更新.
            non_cn_data = load_json(non_cn_path).get("rules",[])
            updated_non_cn_data = merge_rules(non_cn_data, updated_non_cn_data)

            # !cn 增量更新，cn不变
            final_non_cn_data = updated_non_cn_data
            final_cn_data = cn_data

            final_non_cn_data = deduplicate_json(final_non_cn_data)
            final_non_cn_data = convert_sets_to_lists(final_non_cn_data)

            # 保存去重后的非cn文件
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @cn 文件
        elif cn_files and not non_cn_files:
            cn_path = os.path.join(directory, cn_files[0])
            cn_data = load_json(cn_path).get("rules",[])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            non_cn_data = subtract_rules(general_data, cn_data)
            non_cn_path = os.path.join(directory, f"{category}@!cn.json")

            final_non_cn_data = non_cn_data  # 保存非cn数据
            final_cn_data = cn_data  # 保留原始的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @!cn 文件
        elif non_cn_files and not cn_files:
            non_cn_path = os.path.join(directory, non_cn_files[0])
            non_cn_data = load_json(non_cn_path).get("rules",[])

            # 从全体文件中剔除 非cn 文件的规则，更新 cn 文件
            cn_data = subtract_rules(general_data, non_cn_data)
            cn_path = os.path.join(directory, f"{category}@cn.json")

            final_non_cn_data = non_cn_data  # 保留原始的非cn数据
            final_cn_data = cn_data  # 更新后的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        else:
            logging.info(f"跳过处理 {category}，因为没有 @cn 或 @!cn 文件")
            return

        try:
            os.remove(general_file_path)
        except OSError as e:
            logging.error(f"删除全体文件 {general_files[0]} 失败: {e}")


    def main(self):
        source_directory = config.source_dir
        output_directory = config.singbox_output_directory

        # 清空 output_directory
        if os.path.exists(output_directory):
            shutil.rmtree(output_directory)
        os.makedirs(output_directory)

        yaml_files = [f for f in os.listdir(source_directory) if f.endswith('.yaml')]
        for yaml_file in yaml_files:
            print('正在处理{}'.format(yaml_file))
            yaml_file_path = os.path.join(source_directory, yaml_file)
            # 检查 adg文件
            if any(keyword in yaml_file for keyword in config.adg_keyword):
                self.parse_adguard_file(yaml_file_path, output_directory)
            else:
                self.parse_yaml_file(yaml_file_path, output_directory)

        # 生成 SRS 文件
        self.process_category_files(output_directory) # 拆分!cn规则 与 cn规则
        json_files = [f for f in os.listdir(output_directory) if f.endswith('.json')]
        for json_file in json_files:
            json_file_path = os.path.join(output_directory, json_file)
            srs_path = json_file_path.replace(".json", ".srs")
            os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")
            logging.debug(f"成功生成 SRS 文件 {srs_path}")

        #### 调用工具函数 将 sing-box 规则转化为 Surge/Shadowrocket 规则
        convert_json_to_surge(output_directory)
        convert_json_to_clash(output_directory)

        convert_yaml_to_mrs(config.clash_output_directory)

if __name__ == "__main__":
    # 使用类的实例
    rule_parser = RuleParser()
    rule_parser.main()
