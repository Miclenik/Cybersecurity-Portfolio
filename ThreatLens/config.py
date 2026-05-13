from dotenv import load_dotenv
import os

load_dotenv("apikeys.env")

VT_API_KEY = os.getenv("VT_API_KEY")
HYBRID_API_KEY = os.getenv("HYBRID_API_KEY")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")
GEMINI_API_KEY=os.getenv("GEMINI_API_KEY")
GROQ_API_KEY=os.getenv("GROQ_API_KEY")