# L0 框架层 — 只读,直接复用公开标准

本层导入公开 STIX/JSON,不自建:

- `mitre_attack/` — MITRE ATT&CK Enterprise (STIX bundle,每季度同步)
  - 来源: https://github.com/mitre/cti
- `mitre_d3fend/` — MITRE D3FEND (防御技术对抗 ATT&CK)
- `nist_csf/` — NIST CSF 2.0 (Identify/Protect/Detect/Respond/Recover)
- `dengbao_2_0/` — 等保 2.0 (GB/T 22239-2019,三道防线 + 5 级保护)
- `mitre_atlas/` — MITRE ATLAS (AI 系统威胁,为 Agent 自身安全服务)

导入脚本 (W5-6 实现):
```python
# scripts/import_mitre.py
# 从 https://raw.githubusercontent.com/mitre/cti/master/ 拉 STIX bundle
# 向量化 → Qdrant collection "l0_framework"
```
