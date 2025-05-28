from setuptools import setup, find_packages

setup(
    name="quantum-chat-backend",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "flask",
        "flask-socketio",
        "flask-cors",
        "quantcrypt",
        "cryptography",
        "eventlet",
        "gunicorn",
        "bcrypt",
        "python-dotenv",
    ],
)
