# Ollama Models

CyberGuard uses these models when `AI_PROVIDER=ollama`:

| Model | Purpose | Approximate download | Status |
| --- | --- | ---: | --- |
| `dolphin3:8b` | General analysis and summaries | 4.9 GB | Installed |
| `hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF` | Security analysis, reasoning, and attack planning | 6.6 GB | Not installed yet |

BaronLLM is a public (MIT-licensed) Llama-3.1-8B-Instruct fine-tune for offensive security, distributed as a Q6_K GGUF.

## Install

Pull the general model from the Ollama Library:

```powershell
ollama pull dolphin3:8b
```

Pull the security model through Ollama's Hugging Face integration. The `hf.co/` prefix is part of the model tag and must be included:

```powershell
ollama pull hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
```

Until BaronLLM is installed, the engine falls back to the general model for security analysis (logged at startup as `Security model ... not found`). The previously used `hf.co/Mungert/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` and `xploiter/pentester:latest` are also installed and can be substituted via `.env` if needed.

## Configure CyberGuard

The code defaults already use the full `hf.co/` tag, so no `.env` overrides are required once the models are installed. To override:

```dotenv
AI_PROVIDER=ollama
GENERAL_MODEL=dolphin3:8b
SECURITY_MODEL=hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
REASONING_MODEL=hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
```

Confirm both models are installed with:

```powershell
ollama list
```

When `AI_PROVIDER=openai` and `AI_API_KEY` is configured, CyberGuard uses the OpenAI-compatible provider instead and does not require these Ollama models.
