import boto3
bedrock = boto3.client("bedrock-runtime")

def guard(text: str, source: str) -> bool:
    r = bedrock.apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID, guardrailVersion="DRAFT",
        source=source,                      # "INPUT" for retrieved chunks, "OUTPUT" for responses
        content=[{"text": {"text": text}}])
    return r["action"] == "NONE"           # "GUARDRAIL_INTERVENED" means block or mask
