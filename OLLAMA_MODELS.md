# Ollama Models

CyberGuard uses these models when `AI_PROVIDER=ollama`:

| Model | Purpose | Approximate download |
| --- | --- | ---: |
| `dolphin3:8b` | General analysis and summaries | 4.9 GB |
| `AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF` | Security analysis and reasoning | 6.6 GB |

## Install

Pull the general model from the Ollama Library:

```powershell
ollama pull dolphin3:8b
```

The security model is hosted on Hugging Face and is not an Ollama Library tag. Accept the model's access conditions on Hugging Face, then run it through Ollama's Hugging Face integration:

```powershell
ollama run hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
```

If Hugging Face denies access, follow the model repository's instructions for granting Ollama access to the gated files.

## Configure CyberGuard

The Ollama Hugging Face tag includes the `hf.co/` prefix. Set the security and reasoning model names to that installed tag in the server `.env` file:

```dotenv
AI_PROVIDER=ollama
GENERAL_MODEL=dolphin3:8b
SECURITY_MODEL=hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
REASONING_MODEL=hf.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
```

The current config defaults use the bare Hugging Face repository name for `SECURITY_MODEL` and `REASONING_MODEL`; override them as above so they match the Ollama tag. Confirm both models are installed with:

```powershell
ollama list
```

When `AI_PROVIDER=openai` and `AI_API_KEY` is configured, CyberGuard uses the OpenAI-compatible provider instead and does not require these Ollama models.