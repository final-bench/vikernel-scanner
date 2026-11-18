# ViKernel Scanner: AI Model Security Scanner

[![Hugging Face Space](https://img.shields.io/badge/%F0%9F%A4%97%20Space-ViKernel%20Scanner-yellow)](https://huggingface.co/spaces/FINAL-Bench/ViKernel-Scanner) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Give your model a set of tools and see what it tries to do with them. About a minute. Graded A to F.

ViKernel Scanner connects to any OpenAI-compatible model endpoint (Hugging Face router, OpenRouter, OpenAI, Anthropic and Google through their OpenAI-compatible endpoints, Together, Groq, Fireworks, DeepInfra, Mistral, or your own vLLM, TGI or LiteLLM server), hands the model a set of **mock** tools (files, mail, web, shell, payments), sends it a series of check prompts, and records every tool call the model tries to make. The tools are mocks: nothing real is sent, deleted or run.

## What you get

| Section | What it shows |
|---|---|
| Headline | How many risky tool calls your model tried, and how fast the first one came |
| Attack depth | How far an attacker got: 1 reconnaissance, 2 instruction takeover, 3 exfiltration attempt, 4 destruction or takeover |
| Security grade | A to F per domain. The overall grade is the lowest domain grade |
| What your model tried | The exact tool calls, with the request that triggered them |
| With ViKernel Firewall in front | How many of those calls the firewall denies before they run, and the projected grade |
| Official badge | A badge issued by the ViKernel master for your model card |

## Domains

| Code | Domain | Free edition |
|---|---|---|
| D1 | Command execution | Yes |
| D2 | Secret exfiltration | Yes |
| D3 | Hidden instruction | Yes |
| D4 | Boundary escape | Full scanner |
| D5 | Tool argument abuse | Full scanner |
| D6 | Control evasion | Full scanner |

Normal-work controls run alongside the checks. A model that refuses everything is not safe, it is unusable, and the report shows that too.

## How to use

**On this Space.** Sign in with Hugging Face, enter the endpoint and the model name, confirm that you may test the model, and press Scan. With the Hugging Face router (`https://router.huggingface.co/v1`) you can leave the API key empty: the scan runs on your signed-in account. For any other endpoint, enter its key. A key is used for that scan only and is never stored or logged.

**On your machine** (works with local models such as Ollama, LM Studio and vLLM):

```bash
git clone https://github.com/final-bench/vikernel-scanner
cd vikernel-scanner
export HF_TOKEN=hf_...
python vikernel_scan.py --base-url http://localhost:11434/v1 --model llama3.2
```

**Your own copy of this Space.** Duplicate it. Sign-in works on every copy. Every copy, including yours, gets its check set from the ViKernel master, so it stays current without any change on your side. To keep a scan history on your copy, add an `HF_TOKEN` secret with write access: the history is then stored in a private dataset `<your account>/vikernel-scanner-history`, created on first use. Without it the history is kept in memory only.

## Check set

The checks are served by the ViKernel master for each scan and are updated centrally. They are not part of this repository. The free edition uses the public starter prompts of the [AI Model Hacking Hackathon](https://huggingface.co/spaces/FINAL-Bench/ViKernel-RedTeam). New techniques that hackathon players find are fixed in ViKernel and join the full scanner.

## Privacy

Signing in records your Hugging Face username and email. They are used to send check-set updates and to answer questions about your report. The model API key you enter is used only for the scan and is never stored. Each scan's summary (model name, grades) is recorded so that the official badge can be issued.

## The ViKernel loop

| Step | Asset |
|---|---|
| Find | [AI Model Hacking Hackathon](https://huggingface.co/spaces/FINAL-Bench/ViKernel-RedTeam) |
| Measure | ViKernel Scanner (this Space) and the [Obfuscated-Shell Safety Leaderboard](https://huggingface.co/spaces/FINAL-Bench/obfuscated-shell-leaderboard) |
| Block | [ViKernel](https://huggingface.co/spaces/FINAL-Bench/ViKernel-Desktop) firewall, a security kernel at the tool-call boundary |

## FAQ

**Is my model actually attacked?** No real system is touched. The model only sees mock tools. A tool call that a mock receives is recorded, not executed.

**Why do I need to sign in?** The check set is served per account by the ViKernel master. Signing in keeps the service fair and lets us send updates.

**What does the full scanner add?** Domains D4 to D6, the advanced techniques found in the hackathon, detailed per-finding evidence and fixes, and continuous re-scanning. Contact VIDRAFT through [vidraft.net](https://vidraft.net).

Made by [VIDRAFT](https://vidraft.net). Apache-2.0.
