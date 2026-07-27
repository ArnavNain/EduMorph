import os
import json
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from groq import Groq
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# Path detection for local execution or Vercel deployment
base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates') if os.path.exists(os.path.join(base_dir, 'templates')) else os.path.join(base_dir, '../templates')
app = Flask(__name__, template_folder=template_dir)

# Initialize Groq client
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

# Initialize Supabase client
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY) if (SUPABASE_URL and SUPABASE_ANON_KEY) else None

# Search provider (Tavily) - used for real, live retrieval so the "Verify" and
# "Resources" features are grounded in actual web results instead of the
# model's own memory, which cannot guarantee current or working links.
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")
TAVILY_ENDPOINT = "https://api.tavily.com/search"

# Domains that generally indicate a more reputable / authoritative source.
# Used only to bias ranking towards higher-quality material - Tavily's own
# relevance score is still the primary signal.
REPUTABLE_DOMAIN_HINTS = (
    ".gov", ".edu", ".ac.uk", "wikipedia.org", "nature.com", "sciencedirect.com",
    "who.int", "nih.gov", "britannica.com", "reuters.com", "apnews.com",
    "bbc.com", "nytimes.com", "wsj.com", "khanacademy.org", "mit.edu",
    "stanford.edu", "harvard.edu", "ieee.org", "springer.com", "jstor.org"
)


def run_web_search(query, max_results=8):
    """Call the Tavily search API and return a normalized list of results.

    Returns a list of dicts: {title, url, content, score}. Returns an empty
    list (never raises) if the provider isn't configured or the call fails,
    so callers can show an honest "no sources found" state.
    """
    if not TAVILY_API_KEY or not query:
        return []

    try:
        resp = requests.post(
            TAVILY_ENDPOINT,
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "search_depth": "advanced",
                "max_results": max_results,
                "include_answer": False,
                "include_raw_content": False,
            },
            timeout=15
        )
        resp.raise_for_status()
        payload = resp.json()
        raw_results = payload.get("results", []) or []

        normalized = []
        for r in raw_results:
            url = (r.get("url") or "").strip()
            if not url:
                continue
            normalized.append({
                "title": (r.get("title") or url).strip(),
                "url": url,
                "content": (r.get("content") or "").strip(),
                "score": r.get("score", 0)
            })

        # Nudge reputable domains toward the top without discarding others.
        def sort_key(item):
            is_reputable = any(hint in item["url"].lower() for hint in REPUTABLE_DOMAIN_HINTS)
            return (0 if is_reputable else 1, -float(item.get("score") or 0))

        normalized.sort(key=sort_key)
        return normalized
    except Exception:
        return []


@app.route('/')
def home():
    return render_template(
        'index.html',
        supabase_url=SUPABASE_URL,
        supabase_anon_key=SUPABASE_ANON_KEY
    )

@app.route('/api/signup', methods=['POST'])
def signup():
    if not supabase:
        return jsonify({"error": "Supabase client is not configured."}), 500

    data = request.get_json() or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required."}), 400

    try:
        # Check if user already exists
        existing_user = supabase.table('users').select('*').eq('email', email).execute()
        if existing_user.data and len(existing_user.data) > 0:
            return jsonify({"error": "An account with this email already exists."}), 400

        hashed_password = generate_password_hash(password)

        insert_response = supabase.table('users').insert({
            "name": name,
            "email": email,
            "password": hashed_password
        }).execute()

        if insert_response.data:
            return jsonify({
                "success": True, 
                "user": {"name": name, "email": email}
            })
        else:
            return jsonify({"error": "Failed to create account in database."}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    if not supabase:
        return jsonify({"error": "Supabase client is not configured."}), 500

    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({"error": "Username/Email and password are required."}), 400

    try:
        # Query by email first, fallback to name
        response = supabase.table('users').select('*').eq('email', email).execute()
        users = response.data

        if not users:
            response = supabase.table('users').select('*').eq('name', email).execute()
            users = response.data

        if not users or len(users) == 0:
            return jsonify({"error": "Invalid username/email or password credentials."}), 401

        user = users[0]

        if not check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid username/email or password credentials."}), 401

        return jsonify({
            "success": True, 
            "user": {"name": user['name'], "email": user['email']}
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    if not supabase:
        return jsonify({"error": "Supabase client is not configured."}), 500

    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    new_password = data.get('new_password', '').strip()

    if not email or not new_password:
        return jsonify({"error": "Email and new password are required."}), 400

    try:
        response = supabase.table('users').select('*').eq('email', email).execute()
        if not response.data or len(response.data) == 0:
            return jsonify({"error": "No registered user account found with this email."}), 404

        hashed_password = generate_password_hash(new_password)

        update_res = supabase.table('users').update({"password": hashed_password}).eq('email', email).execute()

        if update_res.data:
            return jsonify({"success": True, "message": "Password updated successfully."})
        else:
            return jsonify({"error": "Failed to update password."}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/morph-concept', methods=['POST'])
def morph_concept():
    if not client:
        return jsonify({"error": "Groq API Key configuration missing from deployment runtime environment."}), 500

    data = request.get_json() or {}
    topic = data.get('topic', '').strip()
    profile = data.get('profile', 'ELI5').strip()
    depth = data.get('depth', 'Undergrad').strip()
    length = data.get('length', 'Standard').strip()

    if not topic:
        return jsonify({"error": "Target concept query value cannot be empty."}), 400

    # Dynamic length targets calibrated to maximum safe JSON token generation limits
    length_instruction = "approximately 340 words per subsection"
    if length == "Short":
        length_instruction = "approximately 150 words per subsection"
    elif length == "Standard":
        length_instruction = "approximately 340 words per subsection"
    elif length == "Comprehensive":
        length_instruction = "approximately 450 words per subsection"

    system_prompt = (
        "You are an elite AI cognitive adaptation solution architect optimized for US educational paradigms.\n"
        "Your task is to disassemble complex technical topics into exactly 3 subsections, aligned to the user's chosen profile and depth.\n"
        "CRITICAL INSTRUCTIONS:\n"
        f"1. The explanation length for each subsection MUST be {length_instruction} to strictly fulfill the user's length setting.\n"
        "2. The content of the explanation must change dynamically based on the exact topic provided.\n"
        "3. You MUST generate exactly 3 subsections in the array. Never generate 5 items, and NEVER leave items 1 and 4 blank. The array length must be strictly 3.\n"
        "4. Each subsection MUST have a checkpoint question that is DIRECTLY pulled from the unique explanation text generated for that specific subsection.\n"
        "5. You MUST determine the best visual interactive theme for the topic. Pick exactly ONE from this list that best represents the concept requested: 'math', 'chemistry', 'space', or 'general'.\n\n"
        "You MUST return your response exclusively as a valid JSON object matching this exact schema blueprint:\n"
        "{\n"
        "  \"interactive_theme\": \"math | chemistry | space | general\",\n"
        "  \"subsections\": [\n"
        "    {\n"
        "      \"title\": \"Subconcept Title\",\n"
        "      \"content\": \"Highly personalized explanation text reflecting the exact length and depth settings.\",\n"
        "      \"checkpoint\": {\n"
        "        \"question\": \"An engaging multiple choice check question derived directly from this chunk's content.\",\n"
        "        \"options\": [\"Option A\", \"Option B\", \"Option C\", \"Option D\"],\n"
        "        \"correct_index\": 0,\n"
        "        \"explanation\": \"Diagnostic feedback why the choice is correct and others are wrong.\"\n"
        "      }\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "IMPORTANT: Output ONLY valid JSON. Do not wrap your response in markdown text wrappers (like ```json) and do not include any conversational text. Start your response with { and end with }."
    )

    user_prompt = f"""
    Target Academic Concept: {topic}
    Cognitive Personalization Profile Lens: {profile}
    US Academic Depth Tier Setting: {depth}
    Explanation Length Preference: {length}
    """

    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=4096,
            response_format={"type": "json_object"}
        )
        
        response_data = json.loads(completion.choices[0].message.content)
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/generate-evaluation', methods=['POST'])
def generate_evaluation():
    if not client:
        return jsonify({"error": "Groq API Key configuration missing from deployment runtime environment."}), 500

    data = request.get_json() or {}
    topic = data.get('topic', '').strip()
    eval_type = data.get('type', 'Quiz').strip()
    difficulty = data.get('difficulty', 'Intermediate').strip()
    gap_history = data.get('gap_history', [])
    
    # Process dynamic item count
    try:
        count = int(data.get('count', 4))
        if count < 1: count = 1
        if count > 50: count = 50
    except (ValueError, TypeError):
        count = 4

    if not topic:
        return jsonify({"error": "Testing objective concept topic parameter is missing."}), 400

    history_injection = ""
    if gap_history:
        history_elements = "\n- ".join(gap_history)
        history_injection = (
            f"\nCRITICAL PREDICTIVE GAP TARGETING INSTRUCTION:\n"
            f"The student previously demonstrated cognitive friction or answered incorrectly on the following components:\n"
            f"- {history_elements}\n"
            f"You MUST engineering the newly generated evaluation items to specifically target, isolate, and remediate these exact weak sub-topics."
        )

    system_prompt = (
        "You are an expert academic evaluator optimized for US high-performance grading criteria.\n"
        "Generate adaptive test items optimized for active recall based on the requested evaluation format.\n\n"
        "CRITICAL RESPONSE FORMAT RULES:\n"
        "Return EXCLUSIVELY a raw JSON object matching the exact structure requested below.\n\n"
        "If evaluation type is 'Flashcards', return:\n"
        "{\n"
        "  \"items\": [\n"
        "    { \"front\": \"Core technical question targeted for active recall\", \"back\": \"Clear, concise answer explaining the conceptual mechanism\" }\n"
        "  ]\n"
        "}\n\n"
        f"If evaluation type is 'Quiz' or 'Exam', return exactly {count} unique multi-choice questions:\n"
        "{\n"
        "  \"items\": [\n"
        "    {\n"
        "      \"question\": \"Detailed technical conceptual check query\",\n"
        "      \"options\": [\"Option A\", \"Option B\", \"Option C\", \"Option D\"],\n"
        "      \"correct_index\": 0,\n"
        "      \"explanation\": \"Granular diagnostic feedback explicitly explaining why the choice is true and why alternatives fail\"\n"
        "    }\n"
        "  ]\n"
        "}\n"
        "IMPORTANT: Output ONLY valid JSON. Do not wrap your response in markdown text wrappers (like ```json) and do not include any conversational text. Start your response with { and end with }."
    )

    user_prompt = f"""
    Testing Objective Concept: {topic}
    Evaluation System Type: {eval_type}
    Difficulty Tier Target: {difficulty}
    {history_injection}
    
    Execution Matrix Requirements:
    1. Generate exactly {count} distinct highly-targeted evaluation items.
    2. Match structural depth definitions expected by US grading standards for the {difficulty} tier.
    3. Provide definitive analytical reasoning answers for real-time validation checks.
    """

    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.4,
            max_tokens=4096,
            response_format={"type": "json_object"}
        )
        
        response_data = json.loads(completion.choices[0].message.content)
        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/verify-facts', methods=['POST'])
def verify_facts():
    if not client:
        return jsonify({"error": "Groq API Key configuration missing from deployment runtime environment."}), 500
    if not TAVILY_API_KEY:
        return jsonify({"error": "Search provider is not configured (missing TAVILY_API_KEY)."}), 500

    data = request.get_json() or {}
    topic = data.get('topic', '').strip()

    if not topic:
        return jsonify({"error": "Please enter a topic or question to verify."}), 400

    search_results = run_web_search(topic, max_results=8)

    if not search_results:
        return jsonify({
            "answer": "",
            "sources": [],
            "no_sources_found": True
        })

    # Build a numbered source block so the model can only cite what's actually here.
    source_block_lines = []
    for idx, r in enumerate(search_results):
        snippet = r["content"][:1200]
        source_block_lines.append(f"[{idx + 1}] {r['title']} ({r['url']})\n{snippet}")
    source_block = "\n\n".join(source_block_lines)

    system_prompt = (
        "You are a strict source-grounded research assistant. You will be given a topic and a numbered "
        "list of real web search results (title, URL, and content snippet).\n"
        "CRITICAL RULES:\n"
        "1. Base your answer EXCLUSIVELY on the information contained in the provided numbered sources. "
        "Do NOT add facts from your own general knowledge, and do NOT speculate.\n"
        "2. If the provided sources do not contain enough information to answer confidently, say so plainly "
        "instead of filling gaps with assumptions.\n"
        "3. Every factual sentence in your answer must be traceable to at least one numbered source.\n"
        "4. In the 'sources_used' array, include ONLY the numbers of sources you actually drew on for the answer "
        "(omit sources you did not end up using).\n"
        "5. Keep the answer concise, neutral, and factual - a few short paragraphs at most.\n\n"
        "Return your response exclusively as a valid JSON object matching this schema:\n"
        "{\n"
        "  \"answer\": \"Concise answer synthesized only from the provided sources.\",\n"
        "  \"sources_used\": [1, 3]\n"
        "}\n"
        "IMPORTANT: Output ONLY valid JSON. No markdown fences, no conversational text."
    )

    user_prompt = f"Topic / question: {topic}\n\nNumbered sources:\n\n{source_block}"

    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            max_tokens=2048,
            response_format={"type": "json_object"}
        )

        response_data = json.loads(completion.choices[0].message.content)
        used_indices = response_data.get("sources_used", []) or []

        cited_sources = []
        for i in used_indices:
            try:
                idx = int(i) - 1
                if 0 <= idx < len(search_results):
                    src = search_results[idx]
                    cited_sources.append({"title": src["title"], "url": src["url"]})
            except (ValueError, TypeError):
                continue

        # Fall back to showing all retrieved sources if the model didn't mark any as used.
        if not cited_sources:
            cited_sources = [{"title": r["title"], "url": r["url"]} for r in search_results]

        return jsonify({
            "answer": response_data.get("answer", ""),
            "sources": cited_sources,
            "no_sources_found": False
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/find-resources', methods=['POST'])
def find_resources():
    if not client:
        return jsonify({"error": "Groq API Key configuration missing from deployment runtime environment."}), 500
    if not TAVILY_API_KEY:
        return jsonify({"error": "Search provider is not configured (missing TAVILY_API_KEY)."}), 500

    data = request.get_json() or {}
    query = data.get('query', '').strip()

    if not query:
        return jsonify({"error": "Please enter a topic or question to find resources for."}), 400

    search_results = run_web_search(query, max_results=12)

    if not search_results:
        return jsonify({"items": [], "no_sources_found": True})

    source_block_lines = []
    for idx, r in enumerate(search_results):
        snippet = r["content"][:600]
        source_block_lines.append(f"[{idx + 1}] {r['title']} ({r['url']})\n{snippet}")
    source_block = "\n\n".join(source_block_lines)

    system_prompt = (
        "You are a helpful research librarian. You will be given a user's query and a numbered list of real "
        "web search results (title, URL, content snippet).\n"
        "CRITICAL RULES:\n"
        "1. Select the 5 to 10 BEST, most useful, most relevant items from the numbered list below. "
        "Do NOT invent new links or titles - only choose from what is provided.\n"
        "2. If fewer than 5 of the provided sources are genuinely useful, return only the ones that are - "
        "do not pad the list with weak or irrelevant results.\n"
        "3. For each chosen item, write a one-sentence 'why' explaining what the user will get from it.\n"
        "4. Reference each chosen item by its source number.\n\n"
        "Return your response exclusively as a valid JSON object matching this schema:\n"
        "{\n"
        "  \"items\": [\n"
        "    { \"source_number\": 1, \"why\": \"One short sentence on why this resource is useful.\" }\n"
        "  ]\n"
        "}\n"
        "IMPORTANT: Output ONLY valid JSON. No markdown fences, no conversational text."
    )

    user_prompt = f"User query: {query}\n\nNumbered sources:\n\n{source_block}"

    try:
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.2,
            max_tokens=2048,
            response_format={"type": "json_object"}
        )

        response_data = json.loads(completion.choices[0].message.content)
        chosen = response_data.get("items", []) or []

        curated = []
        for item in chosen:
            try:
                idx = int(item.get("source_number")) - 1
                if 0 <= idx < len(search_results):
                    src = search_results[idx]
                    curated.append({
                        "title": src["title"],
                        "url": src["url"],
                        "why": item.get("why", "").strip()
                    })
            except (ValueError, TypeError, AttributeError):
                continue

        return jsonify({"items": curated, "no_sources_found": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("Initializing Local Engine Node at http://127.0.0.1:1500")
    app.run(debug=True, port=1500)