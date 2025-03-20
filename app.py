import os
import google.generativeai as genai
import jwt
import logging as log
from waitress import serve
import time
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
from auth import auth_bp, token_required, get_user_by_username, JWT_SECRET

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

log.basicConfig(level=log.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the Gemini client
genai.configure(api_key="AIzaSyAdHRAWpJwLd2opgx6i7OGVYEISUl-Oz2E")
model = genai.GenerativeModel("gemini-1.5-flash")

def is_valid_code(code: str, language: str) -> bool:
    if not code.strip():
        return False
    try:
        if language.lower() == "python":
            compile(code, "", "exec")
            return True
        elif language.lower() == "javascript":
            return any(kw in code for kw in ["function", "const", "let", "var"])
        elif language.lower() == "java":
            return any(kw in code for kw in ["class", "public", "static"])
        return False
    except SyntaxError:
        return False

def generate_documentation(prompt: str) -> str:
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        log.error(f"Failed to generate documentation: {e}")
        return "Failed to generate output."

def generate_initial_documentation(code: str, language: str) -> str:
    prompt = f"""
    Generate documentation for this {language} code with the following sections:
    1. FUNCTIONALITY: Explain the code's purpose
    2. INPUT/OUTPUT: Describe inputs and outputs
    3. EXAMPLE USAGE: Provide a code example
    4. KEY VARIABLES: List important variables

    CODE:
    ```
    {code}
    ```
    """
    return generate_documentation(prompt)

def generate_overview(documentation: str, language: str) -> str:
    prompt = f"Provide a brief overview of the following {language} code:\n{documentation}"
    return generate_documentation(prompt)

def document_functions(documentation: str, language: str) -> str:
    prompt = f"Extract and document all functions from the following {language} code:\n{documentation}"
    return generate_documentation(prompt)

def document_variables(code: str, language: str) -> str:
    prompt = f"""Extract and document all key variables from this {language} code:
    ```
    {code}
    ```
    FORMAT:
    VariableName: Description
    AnotherVar: Purpose
    """
    return generate_documentation(prompt)

def explain_workflow(documentation: str, language: str) -> str:
    prompt = f"Explain the workflow of the following {language} code:\n{documentation}"
    return generate_documentation(prompt)

def provide_example_usage(documentation: str, language: str) -> str:
    prompt = f"Provide an example usage of the following {language} code:\n{documentation}"
    return generate_documentation(prompt)

@app.route("/")
def index():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('auth.login'))
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = get_user_by_username(data["username"])
        if not user:
            resp = make_response(redirect(url_for('auth.login')))
            resp.delete_cookie('token')
            return resp
        return render_template("index.html", username=data["username"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for('auth.login'))

@app.route("/profile")
@token_required
def profile(current_user):
    return render_template("profile.html", user=current_user)

@app.route("/document")
@token_required
def document(current_user):
    return render_template("Document.html", user=current_user)

@app.route("/generate-docs/", methods=["POST"])
@token_required
def generate_docs(current_user):
    data = request.get_json()
    code = data.get("code", "").strip()
    language = data.get("language", "python").strip()

    if not code:
        log.error("No code provided in the request.")
        return jsonify({"documentation": "No code provided."}), 400

    if not is_valid_code(code, language):
        log.error(f"Invalid {language} code provided: {code}")
        return jsonify({"documentation": "Invalid code provided. Please check the syntax."}), 400

    log.info(f"Input code received: \n{code}")

    try:
        start_time = time.time()
        initial_doc = generate_initial_documentation(code, language)

        if not initial_doc or initial_doc == "Documentation generation failed.":
            log.error("Initial documentation generation failed.")
            return jsonify({"documentation": "Failed to generate initial documentation."}), 500

        overview = generate_overview(initial_doc, language)
        functions_doc = document_functions(initial_doc, language)
        variables_doc = document_variables(code, language)
        workflow = explain_workflow(initial_doc, language)
        example_usage = provide_example_usage(initial_doc, language)

        end_time = time.time()

        documentation = f"""
        Overview:
        {overview}

        Functions:
        {functions_doc}

        Variables:
        {variables_doc}

        Workflow:
        {workflow}

        Example Usage:
        {example_usage}
        """

        log.info(f"Total documentation generation time: {end_time - start_time:.2f} seconds.")
        return jsonify({"documentation": documentation.strip()})

    except Exception as e:
        log.exception("Error generating documentation")
        return jsonify({"documentation": f"Failed to generate documentation: {str(e)}"}), 500

app.register_blueprint(auth_bp, url_prefix='/auth')

if __name__ == "__main__":
    app.run(debug=True)
