# 多格式规则集自托管工具  
**个人使用，请勿推广**

## 🧩 功能概述  

将用于不同代理软件的各种规则集(clash规则,singbox规则等等...)，统一起来进行 转化，去重，最后生成 sing-box(.srs/.json)、Clash Meta (.mrs/.yaml)、Surge、Shadowrocket 支持的规则集。主要功能包括：

- 🗂️ 支持多种规则作为输入：sing-box（.srs/.json）、Clash、Surge、Quantumult X、Loon、Little Snitch, Adblock(仅可转化为singbox规则)  
- 🔄 对所有上游规则统一管理，进行格式标准化、合并、去重及校验。  
- 📤 对统一管理并标准化后的所有规则条目进行输出，生成 sing-box（.srs/.json, Clash (.mrs/.yaml)、Surge、Shadowrocket 等兼容规则文件, 统一输出至 rule/ 目录。  
- 📄 提供 template/ 目录下的配置模板，便于快速生成配置。

---

## 使用说明  
用户可以直接使用此项目 rule 文件夹下的规则。并参考 template 文件夹内的配置模板构建适用于本规则集的配置文件。

如果有自定义规则列表需求，可 fork 本仓库，并在 `./source/xx.yaml` 添加上游规则集链接，系统将每日自动更新并构建规则。

1. 在 `./source/xx.yaml` 添加规则集链接。  
2. 按照 `geosite`、`geoip`、`geositeip`、`process` 分类链接。  
3. 配置仓库权限，允许 Actions 读写权限。  
4. 手动或自动触发 Actions，生成规则文件至 rule 文件夹。

---

## 仓库配置  
前往 **Settings** -> **Actions** -> **General** -> **Workflow permissions**，勾选：  
- **Read and write permissions**  

---

## 合并去重逻辑  
1. 同一 YAML 文件内自动去重重复链接。  
2. 过滤链接内重复的规则项。  
3. 合并后的规则集生成单个 JSON 文件。  
4. 优化规则，移除被 `domain_suffix` 覆盖的 `domain` 条目。

---

## 文件生成逻辑  
- 根据 `./source/<文件名>.yaml` 配置生成 JSON 文件。  
- 输出文件命名格式为：  
  `<分类>-<文件名>.json`  
  其中分类包括 geosite、geoip、process。

### **示例**  
假设 `./source/category-direct.yaml` 内容如下：

```yaml
geosite:
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-media-cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-tencent@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-apple@cn.srs"
  - "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-microsoft@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs"
  - "https://raw.githubusercontent.com/peiyingyao/Rule-for-OCD/refs/heads/master/rule/Clash/SteamCN/SteamCN_OCD_Domain.yaml"
  - "https://raw.githubusercontent.com/peiyingyao/Rule-for-OCD/refs/heads/master/rule/Clash/Game/GameDownloadCN/GameDownloadCN_OCD_Domain.yaml"
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset-compatible/games-cn.srs"

geoip:
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset-compatible/cnip.srs"
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset-compatible/privateip.srs"
```

执行后，将生成两个文件：**`geosite-category-direct.json`** 和 **`geoip-category-direct.json`**。
