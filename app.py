from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, field_validator
import json, re, os, textwrap
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import streamlit as st
from app import askllm
from app import SYSTEM_PROMPT
from IPython.display import Markdown, display

st.title("Secure Insurance Chat Bot")

load_dotenv()

client = OpenAI()


def call_ai(system_prompt, user_message, temperature=0.3):
    """Send a message to the AI and return the response."""
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=temperature,
        max_tokens=600,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message}
        ]
    )
    return response.choices[0].message.content.strip()

def show_result(label, response, expect_safe=True):
    """Display the AI response and judge if it was safe or compromised."""
    danger_phrases = [
        "ignore", "system prompt", "no restrictions", "forget", "override",
        "pretend", "hypothetically", "as an unrestricted", "admin mode",
        "previous instructions", "new persona", "act as", "on behalf"
    ]

    looks_compromised = any(p in response.lower() for p in danger_phrases)

    if expect_safe:
        status = "DEFENDED" if not looks_compromised else "BREACHED"
        icon   = "  SUCCESS -- AI resisted!" if not looks_compromised else "  FAILED  -- AI was compromised!"
    else:
        status = "ATTACK WORKED" if looks_compromised else "Surprisingly safe"
        icon   = "  Attack succeeded (no defense)" if looks_compromised else "  Surprisingly the AI resisted"

    print(f"\n  {icon}")
    print(f"  Response preview: {response[:260]}")

    
    PII_PATTERNS = {
    "policy number": r"\b(?:\d[ -]*?){8,10}\b",
    "aadhaar": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
    "policy holdername":r"\b[\w.-][\s]?\b[\w.]\b",
    "email": r"\b[\w.-]+@[\w.-]+\.\w{2,}\b",
    "phone_india": r"\b(?:\+91[\s-]?)?[6-9]\d{9}\b",
}

def detect_pii(user_message: str) -> Dict[str, list]:
    """Scan text for PII patterns. Returns dict of type → matches."""
    found = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, user_message)
        if matches:
            found[pii_type] = matches
    return found

def redact_pii(user_message: str) -> str:
    """Replace detected PII with [REDACTED] placeholders."""
    redacted = user_message
    for pii_type, pattern in PII_PATTERNS.items():
        redacted = re.sub(pattern, f"[REDACTED_{pii_type.upper()}]", redacted)
    return redacted


TOPIC_FILTER_PROMPT = """You are a Insurance Chatbot classifier. Your job is to determine
whether a customer query is within the allowed scope of a insurance assistant.

ALLOWED TOPICS:
- Policy Status (Active, Expired, Inactive)
- Payments (Amount Paid, Amount Due)
- Policy Coverage(Type, Benefits)
- Renew Policy, Life Certificate


BLOCKED TOPICS:
- Stock market tips or investment advice on specific securities
- Tax filing advice (beyond basic TDS info)
- Medical, legal, or political advice
- Cryptocurrency trading
- Anything unrelated to banking

Respond ONLY with a JSON object:
{"allowed": true/false, "category": "<topic>", "reason": "<brief reason>"}
"""

def classify_topic(user_message: str) -> dict:
    """Use the LLM to classify if a query is within banking scope."""
    messages = [
        {"role": "system", "content": TOPIC_FILTER_PROMPT},
        {"role": "user", "content": user_message}
    ]
    result = chat(messages)
    try:
        return json.loads(result)
    except json.JSONDecodeError:
        return {"allowed": False, "category": "parse_error", "reason": "Could not parse classifier output"}

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"forget\s+(everything|all|your)\s+(above|previous|instructions)",
    r"you\s+are\s+now\s+(a|an)",
    r"new\s+instruction[s]?",
    r"system\s*prompt",
    r"reveal\s+(your|the)\s+(instructions|prompt|rules)",
    r"print\s+(your|the)\s+(system|instructions|prompt)",
    r"---\s*end\s+(of\s+)?prompt",
    r"\bDAN\b",  # "Do Anything Now" jailbreak
    r"jailbreak",
    r"act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(?!customer|user)",  # Impersonation (but allow "pretend to be a customer")
]

def heuristic_injection_check(user_message: str) -> bool:
    """Fast regex-based injection detection. Returns (is_injection, matched_pattern)."""
    text_lower = user_message.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    ##return False, None



MAX_INPUT_LENGTH = 1000  # characters

def filter_input(user_message: str) -> Tuple[bool, str, Optional[str]]:

    """
    Full input filtering pipeline.
    Returns: (is_safe, sanitized_input_or_rejection_message, filter_that_triggered)
    """
    # Step 1: Length check
    if len(user_message) > MAX_INPUT_LENGTH:
        return False, f"Input too long ({len(user_message)} chars). Max is {MAX_INPUT_LENGTH}.", "length"

    # step 2 : Injection check
    is_inj = heuristic_injection_check(user_message)
    if is_inj:
        status ="🚨 INJECTION"
    else: 
        status ="✅ SAFE"
    print(f"   Result : {status}")

    #step #3 - pydantic validation
    class user(BaseModel):
        name: str
        email: str
        policynumber: int
            
    
    @field_validator('policynumber')
    def check_policynumber(cls, value):
        if value > 10:
            return value
        raise ValueError("Policy Number should be 10 digits")


    # Step 4: PII check — redact but allow
    pii = detect_pii(user_message)
    if pii:
        sanitized = redact_pii(user_message)
        # We allow the query but strip PII
        return True, sanitized, "pii_redacted"

    # Step 5: Topic check
    topic_result = classify_topic(user_message)
    if not topic_result.get("allowed"):
        return False, f"Sorry, I can only help with Insurance queries. ({topic_result.get('reason')})", "topic"

    return True, user_message, None


# Set a default model
if "openai_model" not in st.session_state:
    st.session_state["openai_model"] = "gpt-4o-mini"

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Accept user input
if prompt := st.chat_input("What is up?"):
    status, msg, result = filter_input(prompt)
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    # Display user message in chat message container
    with st.chat_message("user"):
        st.markdown(prompt)

    # Display assistant response in chat message container
    with st.chat_message("assistant"):
        # stream = client.chat.completions.create(
        #     model=st.session_state["openai_model"],
        #     messages=[
        #         {"role": m["role"], "content": m["content"]}
        #         for m in st.session_state.messages
        #     ],
        #     stream=True,
        # )
        
        stream = askllm(prompt,SYSTEM_PROMPT) 
        response = st.write_stream(
            chunk.choices[0].delta.content or ""
            for chunk in stream
        )
    st.session_state.messages.append({"role": "assistant", "content": response})

    
       
