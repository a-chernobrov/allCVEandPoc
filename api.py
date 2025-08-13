import json
from flask import Flask, jsonify, request, send_from_directory, render_template_string
from flask_cors import CORS
import sqlite3
from database import create_database

create_database()
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

def get_db_connection():
    conn = sqlite3.connect('cve_data.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/api/cve', methods=['GET', 'POST'])
def handle_cve():
    conn = get_db_connection()
    c = conn.cursor()

    if request.method == 'POST':
        data = request.get_json()
        cve_id = data.get('cve_id')
        year = data.get('year')
        description = data.get('description')
        links = data.get('links', [])

        if not all([cve_id, year, description]):
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            c.execute("SELECT links FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
            result = c.fetchone()
            if result:
                existing_links = json.loads(result['links']) if result['links'] else []
                new_links = [link for link in links if link not in existing_links]
                if new_links:
                    all_links = existing_links + new_links
                    c.execute("UPDATE vulnerabilities SET links = ? WHERE cve_id = ?", (json.dumps(all_links), cve_id))
            else:
                c.execute(
                    "INSERT INTO vulnerabilities (cve_id, year, description, links, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
                    (cve_id, year, description, json.dumps(links))
                )
            conn.commit()
        except sqlite3.Error as e:
            conn.rollback()
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()

        return jsonify({'message': 'CVE processed successfully'}), 201

    # Обработка GET-запроса
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    search_query = request.args.get('search', '', type=str)
    offset = (page - 1) * limit

    base_query = """
        FROM vulnerabilities
        WHERE cve_id LIKE ? OR description LIKE ?
    """
    search_pattern = f'%{search_query}%'
    params = (search_pattern, search_pattern)

    if not search_query:
        base_query = "FROM vulnerabilities"
        params = ()

    count_query = f"SELECT COUNT(*) {base_query}"
    c.execute(count_query, params)
    total_records = c.fetchone()[0]
    
    query = f"""
        SELECT cve_id, year, description, links, created_at
        {base_query}
        ORDER BY created_at DESC, year DESC, cve_id DESC
        LIMIT ? OFFSET ?
    """
    
    c.execute(query, params + (limit, offset))

    cve_list = c.fetchall()
    conn.close()

    return jsonify({
        'total_records': total_records,
        'page': page,
        'limit': limit,
        'data': [{
            'cve_id': row['cve_id'],
            'year': row['year'],
            'description': row['description'],
            'links_count': len(json.loads(row['links'])) if row['links'] and row['links'] != 'null' else 0,
            'created_at': row['created_at']
        } for row in cve_list]
    })

@app.route('/api/cve/total', methods=['GET'])
def get_total_cve():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vulnerabilities")
    total = c.fetchone()[0]
    conn.close()
    return jsonify({'total': total})


@app.route('/api/cve/na/total', methods=['GET'])
def get_total_na_cve():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'")
    total_na = c.fetchone()[0]
    conn.close()
    return jsonify({'total_na': total_na})


@app.route('/api/cve/na', methods=['GET'])
def get_na_cve():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    offset = (page - 1) * limit

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%'")
    total_records = c.fetchone()[0]
    total_pages = (total_records + limit - 1) // limit

    c.execute("SELECT * FROM vulnerabilities WHERE cve_id IS NULL OR cve_id = '' OR cve_id NOT LIKE 'CVE-%' ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
    na_cve_list = c.fetchall()
    conn.close()

    results = [{
        'cve_id': row['cve_id'],
        'year': row['year'],
        'description': row['description'],
        'links': json.loads(row['links']) if row['links'] else [],
        'created_at': row['created_at']
    } for row in na_cve_list]

    return jsonify({
        'total_records': total_records,
        'page': page,
        'limit': limit,
        'data': results
    })


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/api/cve/<path:cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    conn = get_db_connection()
    c = conn.cursor()

    c.execute("SELECT description, links FROM vulnerabilities WHERE cve_id = ?", (cve_id,))
    cve_data = c.fetchone()

    if cve_data is None:
        conn.close()
        return jsonify({'error': 'CVE not found'}), 404

    links = json.loads(cve_data['links']) if cve_data['links'] else []
    description = cve_data['description'] if cve_data else 'No description available.'
    
    conn.close()

    return jsonify({
        'description': description,
        'links': links
    })


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('.', path)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
