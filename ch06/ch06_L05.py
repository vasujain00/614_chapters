from guardrails import Guard, OnFailAction
from guardrails.hub import DetectPII, ProvenanceLLM

guard = Guard().use_many(
    DetectPII(pii_entities=["EMAIL_ADDRESS", "PHONE_NUMBER"], on_fail=OnFailAction.FIX),
    ProvenanceLLM(validation_method="sentence", threshold=0.8, on_fail=OnFailAction.REASK),
)
result = guard(llm_api=call_model, prompt=prompt, metadata={"sources": retrieved_chunks})
