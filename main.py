import configparser
import os
import json
import logging
import subprocess
import time
import yaml
import re
import concurrent.futures
from utils import *
from config import Config
from collections import defaultdict
import tempfile
import shutil
import requests
import pandas as pd

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
            logging.debug(f"获取到的原始数据: {raw_data[:500]}")

            cleaned_raw_data = clean_json_data(raw_data)
            logging.debug(f"清理后的数据: {cleaned_raw_data[:500]}")

            data = json.loads(cleaned_raw_data)
            logging.debug(f"解析后的 JSON 数据: {data}")

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

            logging.debug(f"成功解析链接 {link}，生成 JSON 数据")
            return output_data

        except json.JSONDecodeError:
            logging.error(f"解析 JSON 时出错，从链接 {link} 读取的内容可能不是有效的 JSON。")
            return None
        except Exception as e:
            logging.error(f"处理链接 {link} 时发生未知错误：{e}")
            return None

    def parse_yaml_file(self, yaml_file, output_directory):
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            logging.debug(f"解析的 YAML 数据: {data}")

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
                f"{'-' * 50}"
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

        except requests.exceptions.RequestException as e:
            logging.error(f"下载 JSON 文件失败: {json_file_url}, 错误: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"解析 JSON 文件失败: {json_file_url}, 错误: {e}")
        except Exception as e:
            logging.error(f"处理 JSON 文件时出现未知错误: {e}")

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

            domain_count = len(single_file_stats.get("domain", []))
            domain_suffix_count = len(single_file_stats.get("domain_suffix", []))
            ip_cidr_count = len(single_file_stats.get("ip_cidr", []))
            process_name_count = len(single_file_stats.get("process_name", []))
            domain_regex_count = len(single_file_stats.get("domain_regex", []))

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

            return statistics
        else:
            return self.merge_json(json_file_list, output_file, rule_set_name=rule_set_name)

    def merge_json(self, json_file_list, output_file, rule_set_name,
                   enable_trie_filtering=config.enable_trie_filtering):
        logging.debug(f"正在合并 JSON 文件: {json_file_list}")

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

        merged_rules["domain"] = final_domains

        # 针对 geoip 文件，强制去掉 domain
        if "geoip" in output_file.lower():
            merged_rules["domain"] = set()

        final_rules = [
            {category: list(values)}
            for category, values in merged_rules.items()
            if values
        ]

        if "geoip" in output_file.lower():
            final_rules = [r for r in final_rules if "domain" not in r]

        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump({"version": 4, "rules": final_rules}, file, ensure_ascii=False, indent=4)
        except Exception as e:
            logging.error(f"保存 JSON 文件时出错: {e}")

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
                logging.debug(f"检测到 JSON 文件 {link}，直接返回内容")
                return self.download_and_parse_json(link)

            if link.endswith('.srs'):
                logging.debug(f"检测到 SRS 文件 {link}，正在进行解编译处理")
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

    # 以下 process_category_files、process_single_category、main 保持原样
    # 为简洁起见，这里不重复写

