from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from authlib.integrations.flask_client import OAuth
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse
import random
import time
import logging
import re
import json
import os
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Session security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# app.config['SESSION_COOKIE_SECURE'] = True  # Production HTTPS-la uncomment pannu

# CORS
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST"], "allow_headers": ["Content-Type"]}})

# Rate limiting
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")

# Caching
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# User agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
]

# API Keys
SERPER_API_KEY = os.getenv('SERPER_API_KEY')
APP_URL = os.getenv('APP_URL', 'http://localhost:5000')

# ==================== OAuth Setup ====================
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'}
)

microsoft = oauth.register(
    name='microsoft',
    client_id=os.getenv('MICROSOFT_CLIENT_ID'),
    client_secret=os.getenv('MICROSOFT_CLIENT_SECRET'),
    server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# OAuth Routes
@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    session['user'] = {
        'email': user_info['email'],
        'name': user_info['name'],
        'picture': user_info.get('picture'),
        'provider': 'google'
    }
    session['logged_in'] = True
    return redirect('/')

@app.route('/auth/github')
def github_login():
    redirect_uri = url_for('github_callback', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth/github/callback')
def github_callback():
    token = github.authorize_access_token()
    resp = github.get('user')
    user_info = resp.json()
    email_resp = github.get('user/emails')
    emails = email_resp.json()
    primary_email = next((e['email'] for e in emails if e['primary']), user_info.get('email'))

    session['user'] = {
        'email': primary_email,
        'name': user_info['name'] or user_info['login'],
        'picture': user_info['avatar_url'],
        'provider': 'github'
    }
    session['logged_in'] = True
    return redirect('/')

@app.route('/auth/microsoft')
def microsoft_login():
    redirect_uri = url_for('microsoft_callback', _external=True)
    return microsoft.authorize_redirect(redirect_uri)

@app.route('/auth/microsoft/callback')
def microsoft_callback():
    token = microsoft.authorize_access_token()
    user_info = microsoft.parse_id_token(token)
    session['user'] = {
        'email': user_info['email'],
        'name': user_info['name'],
        'picture': None,
        'provider': 'microsoft'
    }
    session['logged_in'] = True
    return redirect('/')
@app.route('/api/user')
def api_user():
    if 'user' in session:
        user = session['user']
        return jsonify({
            'logged_in': True,
            'name': user.get('name', 'User'),
            'email': user.get('email', ''),
            'picture': user.get('picture')
        })
    elif 'logged_in' in session:  # basic login fallback
        return jsonify({
            'logged_in': True,
            'name': session.get('username', 'User'),
            'email': '',
            'picture': None
        })
    return jsonify({'logged_in': False})


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect('/')

# ==================== Helper Functions (Original + Fixed) ====================

def get_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

def fetch_with_retry(url, headers=None, timeout=15, retries=3):
    for i in range(retries):
        try:
            response = requests.get(url, headers=headers or get_headers(), timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                return response
            elif response.status_code == 429:
                wait_time = 5 * (i + 1)
                logger.warning(f"Rate limited. Waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.warning(f"HTTP {response.status_code} for {url}")
        except requests.Timeout:
            logger.warning(f"Timeout on retry {i+1}/{retries} for {url}")
        except requests.RequestException as e:
            logger.warning(f"Retry {i+1}/{retries} failed: {e}")
            time.sleep(2 * (i + 1))
    return None

def sanitize_input(text, max_length=200):
    if not text:
        return ""
    text = re.sub(r'[^\w\s\-.,!?]', '', text)
    return text.strip()[:max_length]

# ==================== Routes ====================

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if username and password:  # Demo only
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            return jsonify({"status": "success", "message": "Login successful!", "username": username})
        else:
            return jsonify({"status": "error", "message": "Invalid credentials!"}), 401

    return render_template('login.html')

@app.route('/search', methods=['POST'])
@limiter.limit("10 per minute")
def search():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid JSON data"}), 400

        query = sanitize_input(data.get("query", ""))
        search_type = data.get("search_type", "all")

        if not query or len(query) < 2:
            return jsonify({"status": "error", "message": "Query too short! Minimum 2 characters required."}), 400
        if len(query) > 200:
            return jsonify({"status": "error", "message": "Query too long! Maximum 200 characters."}), 400

        valid_types = ["all", "google", "scholar", "articles", "books", "youtube"]
        if search_type not in valid_types:
            return jsonify({"status": "error", "message": f"Invalid search type. Must be one of: {', '.join(valid_types)}"}), 400

        logger.info(f"Search request: query='{query}', type='{search_type}'")
        results = []

        if search_type in ["google", "all"]:
            results.extend(search_google_web(query))
        if search_type in ["scholar", "all"]:
            results.extend(search_google_scholar(query))
        if search_type in ["articles", "all"]:
            results.extend(search_articles(query))
        if search_type in ["books", "all"]:
            results.extend(search_books(query))
        if search_type in ["youtube", "all"]:
            results.extend(search_youtube(query))

        if results:
            return jsonify({"status": "success", "query": query, "count": len(results), "search_type": search_type, "results": results})
        else:
            return jsonify({"status": "error", "message": f"No results found for '{query}'. Try different keywords!", "count": 0, "results": []})

    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({"status": "error", "message": "An error occurred while searching. Please try again."}), 500

# ==================== Search Functions (All Original + Working) ====================

@cache.memoize(timeout=300)
def search_google_web(query, num_results=10):
    results = []
    if not SERPER_API_KEY:
        logger.error("SERPER_API_KEY not configured")
        return results

    payload = {"q": query, "num": num_results, "gl": "in", "hl": "en"}
    headers = {"X-API-KEY": SERPER_API_KEY, "Content-Type": "application/json"}

    try:
        response = requests.post("https://google.serper.dev/search", json=payload, headers=headers, timeout=15)
        if response.status_code != 200:
            logger.error(f"Serper API Error: {response.status_code} - {response.text}")
            return results

        data = response.json()
        for item in data.get("organic", [])[:num_results]:
            link = item.get("link", "")
            domain = urlparse(link).netloc if link else "Unknown"
            results.append({
                "source": "Google Web",
                "title": item.get("title", "No title"),
                "snippet": item.get("snippet", "No description"),
                "url": link,
                "domain": domain,
                "icon": "🔍",
                "type": "web"
            })
    except Exception as e:
        logger.error(f"Serper error: {e}")
    return results

@cache.memoize(timeout=300)
def search_google_scholar(query, num_results=8):
    results = []
    url = f"https://scholar.google.com/scholar?q={quote_plus(query)}&hl=en"
    response = fetch_with_retry(url)
    if not response:
        return results

    soup = BeautifulSoup(response.text, 'html.parser')
    for res in soup.find_all('div', class_='gs_ri')[:num_results]:
        try:
            title_a = res.find('h3', class_='gs_rt').find('a')
            if not title_a:
                continue
            title = title_a.get_text(strip=True)
            link = title_a.get('href', '')
            authors = res.find('div', class_='gs_a').get_text(strip=True) if res.find('div', class_='gs_a') else "Unknown"
            snippet = res.find('div', class_='gs_rs').get_text(strip=True) if res.find('div', class_='gs_rs') else "No abstract"
            citations = res.find('a', string=lambda t: t and 'Cited by' in t).get_text(strip=True) if res.find('a', string=lambda t: t and 'Cited by' in t) else "0 citations"

            results.append({
                "source": "Google Scholar",
                "title": title,
                "snippet": snippet[:300] + "..." if len(snippet) > 300 else snippet,
                "url": link,
                "authors": authors,
                "citations": citations,
                "icon": "🎓",
                "type": "research"
            })
        except:
            continue
    return results

@cache.memoize(timeout=300)
def search_articles(query, num_results=8):
    results = []
    url = f"https://www.google.com/search?q={quote_plus(query)}&tbm=nws&hl=en"
    response = fetch_with_retry(url)
    if not response:
        return results

    soup = BeautifulSoup(response.text, 'html.parser')
    for item in soup.find_all('div', class_='SoaBEf')[:num_results]:
        try:
            a = item.find('a')
            if not a:
                continue
            href = a.get('href', '')
            link = href.split('?q=')[1].split('&')[0] if '?q=' in href else href
            title = item.find('div', class_='MBeuO').get_text(strip=True) if item.find('div', class_='MBeuO') else "No title"
            publisher = item.find('div', class_='CEMjEf').get_text(strip=True) if item.find('div', class_='CEMjEf') else "News"
            snippet = item.find('div', class_='GI74Re').get_text(strip=True) if item.find('div', class_='GI74Re') else "No summary"

            results.append({
                "source": "News",
                "title": title,
                "snippet": snippet[:300] + "..." if len(snippet) > 300 else snippet,
                "url": link,
                "publisher": publisher,
                "icon": "📰",
                "type": "article"
            })
        except:
            continue
    return results

@cache.memoize(timeout=300)
def search_books(query, num_results=10):
    results = []
    url = f"https://www.googleapis.com/books/v1/volumes?q={quote_plus(query)}&maxResults={num_results}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            return results
        data = response.json()
        for item in data.get('items', []):
            info = item.get('volumeInfo', {})
            results.append({
                "source": "Google Books",
                "title": info.get('title', 'No title'),
                "snippet": (info.get('description', 'No description')[:300] + "...") if info.get('description') and len(info.get('description')) > 300 else info.get('description', 'No description'),
                "url": info.get('infoLink') or info.get('previewLink', ''),
                "authors": ', '.join(info.get('authors', ['Unknown'])),
                "published": info.get('publishedDate', 'N/A'),
                "pages": info.get('pageCount', 'N/A'),
                "icon": "📚",
                "type": "book"
            })
    except:
        pass
    return results[:num_results]

@cache.memoize(timeout=300)
def search_youtube(query, num_results=8):
    results = []
    url = f"https://www.youtube.com/results?search_query={quote_plus(query)}"
    response = fetch_with_retry(url)
    if not response:
        return results

    soup = BeautifulSoup(response.text, 'html.parser')
    for script in soup.find_all('script'):
        if script.string and 'var ytInitialData' in script.string:
            try:
                match = re.search(r'var ytInitialData = (\{.*?\});', script.string)
                if not match:
                    continue
                data = json.loads(match.group(1))
                items = data.get('contents', {}).get('twoColumnSearchResultsRenderer', {}).get('primaryContents', {}).get('sectionListRenderer', {}).get('contents', [{}])[0].get('itemSectionRenderer', {}).get('contents', [])
                for item in items:
                    renderer = item.get('videoRenderer')
                    if not renderer or len(results) >= num_results:
                        continue
                    video_id = renderer.get('videoId')
                    title = renderer.get('title', {}).get('runs', [{}])[0].get('text', 'No title')
                    channel = renderer.get('longBylineText', {}).get('runs', [{}])[0].get('text', 'Unknown')
                    views = renderer.get('viewCountText', {}).get('simpleText', 'No views')
                    duration = renderer.get('lengthText', {}).get('simpleText', 'Live')
                    results.append({
                        "source": "YouTube",
                        "title": title,
                        "snippet": f"{channel} • {views} • {duration}",
                        "url": f"https://www.youtube.com/watch?v={video_id}",
                        "thumbnail": f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg",
                        "channel": channel,
                        "views": views,
                        "duration": duration,
                        "icon": "📺",
                        "type": "video"
                    })
                if results:
                    break
            except:
                continue
    return results

# ==================== Error Handlers & Health ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"status": "error", "message": "Endpoint not found"}), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    return jsonify({"status": "error", "message": "Rate limit exceeded. Please try again later."}), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({"status": "error", "message": "Internal server error. Please try again."}), 500

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Advanced Search Engine",
        "features": ["Web", "Scholar", "News", "Books", "YouTube"],
        "serper_configured": bool(SERPER_API_KEY)
    })


if __name__ == "__main__":
    print("=" * 60)
    print("Nexus AI Search Engine with OAuth Ready!")
    print("Login: Basic + Google + GitHub + Microsoft")
    print("All Features Working • No More Pylance Errors!")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
