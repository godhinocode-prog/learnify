from flask import Flask, jsonify, request, session
import json
import os
import hashlib
import hmac
import base64
import time
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        from flask import make_response
        res = make_response()
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        res.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return res, 200

# ── In-memory stores ──────────────────────────────────────────────────────────
users_db = {}   # { username: { password_hash, email, interests, joined } }
sessions = {}   # { token: { username, expires } }

# ── Load course data ──────────────────────────────────────────────────────────
DATA_PATH = os.path.join(os.path.dirname(__file__), "data.json")
with open(DATA_PATH, encoding="utf-8") as f:
    COURSE_DATA = json.load(f)

# ── Encryption helpers ────────────────────────────────────────────────────────
ENCRYPT_KEY = b"learnify-secret-key-2024"

def xor_encrypt(data: str, key: bytes) -> str:
    data_bytes = data.encode()
    key_repeated = (key * (len(data_bytes) // len(key) + 1))[:len(data_bytes)]
    encrypted = bytes(a ^ b for a, b in zip(data_bytes, key_repeated))
    return base64.b64encode(encrypted).decode()

def xor_decrypt(data: str, key: bytes) -> str:
    try:
        encrypted = base64.b64decode(data.encode())
        key_repeated = (key * (len(encrypted) // len(key) + 1))[:len(encrypted)]
        decrypted = bytes(a ^ b for a, b in zip(encrypted, key_repeated))
        return decrypted.decode()
    except Exception:
        return ""

def encrypt_payload(payload: dict) -> dict:
    raw = json.dumps(payload)
    encrypted = xor_encrypt(raw, ENCRYPT_KEY)
    # BUG FIX 1: hmac.new() → hmac.new() is valid but the correct modern call is hmac.new(key, msg, digestmod)
    # The key must be bytes; ENCRYPT_KEY is already bytes — correct.
    # BUG FIX 2: hashlib.sha256 must be passed as a callable (no parentheses) — was already correct.
    sig = hmac.new(ENCRYPT_KEY, encrypted.encode(), hashlib.sha256).hexdigest()
    return {"data": encrypted, "sig": sig, "ts": int(time.time())}

def decrypt_payload(envelope: dict) -> dict | None:
    # BUG FIX 3: envelope could be None if request body is missing/not JSON
    if not envelope or not isinstance(envelope, dict):
        return None
    data = envelope.get("data", "")
    sig = envelope.get("sig", "")
    expected = hmac.new(ENCRYPT_KEY, data.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    raw = xor_decrypt(data, ENCRYPT_KEY)
    # BUG FIX 4: json.loads can raise if raw is empty string (xor_decrypt failure)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

def hash_password(pw: str) -> str:
    salt = b"learnify_salt_2024"
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100_000).hex()

def create_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    sessions[token] = {"username": username, "expires": time.time() + 86400}
    return token

def validate_token(token: str) -> str | None:
    entry = sessions.get(token)
    if not entry:
        return None
    if time.time() > entry["expires"]:
        del sessions[token]
        return None
    return entry["username"]

def auth_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        username = validate_token(token)
        if not username:
            return jsonify({"error": "Unauthorized"}), 401
        request.current_user = username
        return f(*args, **kwargs)
    return wrapper

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    envelope = request.json
    payload = decrypt_payload(envelope)
    if not payload:
        return jsonify({"error": "Invalid or tampered payload"}), 400

    username = payload.get("username", "").strip().lower()
    password = payload.get("password", "")
    email = payload.get("email", "").strip().lower()
    interests = payload.get("interests", [])

    if not username or not password or not email:
        return jsonify({"error": "Username, password, and email are required"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if username in users_db:
        return jsonify({"error": "Username already taken"}), 409

    users_db[username] = {
        "password_hash": hash_password(password),
        "email": email,
        "interests": interests,
        "joined": int(time.time()),
        "completed_lessons": [],
        "quiz_scores": {}
    }

    token = create_token(username)
    response = {
        "token": token,
        "user": {
            "username": username,
            "email": email,
            "interests": interests,
            "joined": users_db[username]["joined"]
        }
    }
    return jsonify(encrypt_payload(response)), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    envelope = request.json
    payload = decrypt_payload(envelope)
    if not payload:
        return jsonify({"error": "Invalid or tampered payload"}), 400

    username = payload.get("username", "").strip().lower()
    password = payload.get("password", "")

    user = users_db.get(username)
    if not user or user["password_hash"] != hash_password(password):
        return jsonify({"error": "Invalid username or password"}), 401

    token = create_token(username)
    response = {
        "token": token,
        "user": {
            "username": username,
            "email": user["email"],
            "interests": user["interests"],
            "joined": user["joined"],
            "completed_lessons": user["completed_lessons"],
            "quiz_scores": user["quiz_scores"]
        }
    }
    return jsonify(encrypt_payload(response)), 200

@app.route("/api/auth/logout", methods=["POST"])
@auth_required
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    sessions.pop(token, None)
    return jsonify({"message": "Logged out successfully"})

@app.route("/api/auth/me", methods=["GET"])
@auth_required
def get_me():
    username = request.current_user
    user = users_db[username]
    return jsonify({
        "username": username,
        "email": user["email"],
        "interests": user["interests"],
        "joined": user["joined"],
        "completed_lessons": user["completed_lessons"],
        "quiz_scores": user["quiz_scores"]
    })

# ── Course data routes ────────────────────────────────────────────────────────
@app.route("/api/topics", methods=["GET"])
def get_topics():
    topics = [{
        "id": t["id"],
        "title": t["title"],
        "category": t["category"],
        "icon": t["icon"],
        "color": t["color"],
        "description": t["description"],
        "lesson_count": len(t["lessons"])
    } for t in COURSE_DATA["topics"]]
    return jsonify({"topics": topics})

@app.route("/api/topics/<topic_id>", methods=["GET"])
def get_topic(topic_id):
    topic = next((t for t in COURSE_DATA["topics"] if t["id"] == topic_id), None)
    if not topic:
        return jsonify({"error": "Topic not found"}), 404
    return jsonify(topic)

@app.route("/api/topics/<topic_id>/lessons/<lesson_id>", methods=["GET"])
@auth_required
def get_lesson(topic_id, lesson_id):
    topic = next((t for t in COURSE_DATA["topics"] if t["id"] == topic_id), None)
    if not topic:
        return jsonify({"error": "Topic not found"}), 404
    lesson = next((l for l in topic["lessons"] if l["id"] == lesson_id), None)
    if not lesson:
        return jsonify({"error": "Lesson not found"}), 404
    return jsonify(lesson)

@app.route("/api/topics/<topic_id>/lessons/<lesson_id>/complete", methods=["POST"])
@auth_required
def complete_lesson(topic_id, lesson_id):
    username = request.current_user
    lesson_key = f"{topic_id}:{lesson_id}"
    if lesson_key not in users_db[username]["completed_lessons"]:
        users_db[username]["completed_lessons"].append(lesson_key)
    return jsonify({"completed": users_db[username]["completed_lessons"]})

@app.route("/api/topics/<topic_id>/lessons/<lesson_id>/quiz", methods=["GET"])
@auth_required
def get_quiz(topic_id, lesson_id):
    topic = next((t for t in COURSE_DATA["topics"] if t["id"] == topic_id), None)
    if not topic:
        return jsonify({"error": "Topic not found"}), 404
    lesson = next((l for l in topic["lessons"] if l["id"] == lesson_id), None)
    if not lesson:
        return jsonify({"error": "Lesson not found"}), 404
    # Return quiz without correct answers
    quiz_no_answers = [{
        "question": q["question"],
        "options": q["options"]
    } for q in lesson.get("quiz", [])]
    return jsonify({"quiz": quiz_no_answers})

@app.route("/api/topics/<topic_id>/lessons/<lesson_id>/quiz/submit", methods=["POST"])
@auth_required
def submit_quiz(topic_id, lesson_id):
    username = request.current_user
    data = request.json
    # BUG FIX 5: data could be None if request body is missing/not JSON
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    answers = data.get("answers", [])

    topic = next((t for t in COURSE_DATA["topics"] if t["id"] == topic_id), None)
    # BUG FIX 6: topic not found was silently passed to lesson lookup, causing AttributeError
    if not topic:
        return jsonify({"error": "Topic not found"}), 404
    lesson = next((l for l in topic["lessons"] if l["id"] == lesson_id), None)
    if not lesson:
        return jsonify({"error": "Lesson not found"}), 404

    quiz = lesson.get("quiz", [])
    results = []
    score = 0
    for i, q in enumerate(quiz):
        user_ans = answers[i] if i < len(answers) else -1
        correct = q["answer"]
        is_correct = user_ans == correct
        if is_correct:
            score += 1
        results.append({
            "question": q["question"],
            "your_answer": user_ans,
            "correct_answer": correct,
            "correct_option": q["options"][correct],
            "is_correct": is_correct,
            "explanation": q["explanation"]
        })

    pct = round(score / len(quiz) * 100) if quiz else 0
    quiz_key = f"{topic_id}:{lesson_id}"
    users_db[username]["quiz_scores"][quiz_key] = pct

    return jsonify({"score": score, "total": len(quiz), "percentage": pct, "results": results})

@app.route("/api/recommendations/<topic_id>", methods=["GET"])
def get_recommendations(topic_id):
    rec_ids = COURSE_DATA["recommendations"].get(topic_id, [])
    topics = {t["id"]: t for t in COURSE_DATA["topics"]}
    recommendations = [{
        "id": t_id,
        "title": topics[t_id]["title"],
        "icon": topics[t_id]["icon"],
        "color": topics[t_id]["color"],
        "description": topics[t_id]["description"]
    } for t_id in rec_ids if t_id in topics]
    return jsonify({"recommendations": recommendations})

# ── AI explanations endpoint ──────────────────────────────────────────────────
@app.route("/api/ai/explain", methods=["POST"])
@auth_required
def ai_explain():
    data = request.json
    # BUG FIX 7: data could be None if request body is missing/not JSON
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    question = data.get("question", "")
    context = data.get("context", "")
    topic = data.get("topic", "")

    # Simulated AI responses based on context
    ai_responses = {
        "default": f"Great question about '{topic}'! Here's a detailed explanation:\n\n"
                   f"This concept is fundamental to understanding the subject matter. "
                   f"When we examine '{question}', we need to consider the underlying principles.\n\n"
                   f"Think of it this way: every complex system can be broken down into simpler components. "
                   f"By understanding each part, we can grasp the whole.\n\n"
                   f"Key takeaways:\n• Start with the fundamentals\n• Practice regularly\n• Connect concepts to real-world applications\n\n"
                   f"Context: {context[:200] if context else 'No additional context provided.'}"
    }

    # Topic-specific AI responses
    explanations = {
        "ai": "Artificial Intelligence mimics human cognitive functions. The key insight is that machines can learn patterns from data rather than being explicitly programmed. Think of it like teaching a child — you show examples, not write rules.",
        "cs": "Computer Science is about solving problems efficiently. Algorithms and data structures are the tools of the trade. The best programmers think about time complexity (how fast) and space complexity (how much memory) simultaneously.",
        "physics": "Physics describes reality through mathematical relationships. Newton's laws work because they describe patterns observed consistently in nature. Modern physics (quantum mechanics, relativity) shows these are approximations that break down at extremes.",
        "chemistry": "Chemistry is about how atoms interact based on their electron configurations. The periodic table is organized by electron structure, which determines chemical behavior. Reactions occur when atoms seek more stable electron arrangements.",
        "eee": "Electrical engineering harnesses the movement of electrons. Ohm's Law (V=IR) is the Rosetta Stone of circuits — once you understand it, everything else follows. Power is always about energy transfer per unit time.",
        "ce": "Computer engineering bridges hardware and software. Digital logic uses binary because electronics naturally have two stable states (on/off). Building complex systems from simple gates is the art of digital design.",
    }

    topic_id = topic.split("-")[0] if "-" in topic else topic
    ai_message = explanations.get(topic_id, ai_responses["default"])

    if question:
        ai_message = f"Regarding your question: **'{question}'**\n\n" + ai_message + f"\n\n💡 Pro tip: Try the hands-on activity to reinforce this concept!"

    return jsonify({"explanation": ai_message, "topic": topic})

@app.route("/api/user/interests", methods=["PUT"])
@auth_required
def update_interests():
    username = request.current_user
    data = request.json
    # BUG FIX 8: data could be None if request body is missing/not JSON
    if not data:
        return jsonify({"error": "Invalid request body"}), 400
    interests = data.get("interests", [])
    users_db[username]["interests"] = interests
    return jsonify({"interests": interests})

@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify({
        "total_topics": len(COURSE_DATA["topics"]),
        "total_lessons": sum(len(t["lessons"]) for t in COURSE_DATA["topics"]),
        "total_users": len(users_db)
    })

if __name__ == "__main__":
    print("🚀 Learnify server starting on http://localhost:5000")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
