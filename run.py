#!/usr/bin/env python3
"""
Entry point for the Policy-Driven Anonymity Controller application
Run this file to start the Flask web server
"""
import os
import sys
from app import create_app

# Create the Flask application instance
app = create_app()

if __name__ == '__main__':
    # Get configuration from environment variables or use defaults
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')

    # Print startup banner
    print("=" * 70)
    print("   POLICY-DRIVEN ANONYMITY CONTROLLER")
    print("   Educational Cybersecurity Project")
    print("=" * 70)
    print()
    print(f"🚀 Starting server at http://{host}:{port}")
    print(f"🔧 Debug mode: {debug_mode}")
    print(f"🌐 Environment: {'Development' if debug_mode else 'Production'}")
    print()
    print("📋 IMPORTANT: Make sure these services are running:")
    print()
    print("   1. OPA Server (Required)")
    print("      Command: opa run --server --addr localhost:8181 opa/")
    print("      Status URL: http://localhost:8181/health")
    print()
    print("   2. Tor Service (Optional but recommended)")
    print("      Ubuntu/Debian: sudo service tor start")
    print("      macOS: brew services start tor")
    print("      Test: curl --socks5 127.0.0.1:9050 http://check.torproject.org")
    print()
    print("=" * 70)
    print()
    print("📖 Quick Start Guide:")
    print("   • Open browser: http://localhost:5000")
    print("   • Dashboard shows system status")
    print("   • Test anonymity requests in the request form")
    print("   • View monitoring at: http://localhost:5000/monitoring")
    print("   • Configure policies at: http://localhost:5000/policy-config")
    print()
    print("⚠️  For Educational Use Only - Not for Production!")
    print()
    print("=" * 70)
    print()

    try:
        # Check if OPA is running
        import requests
        try:
            response = requests.get('http://localhost:8181/health', timeout=2)
            if response.status_code == 200:
                print("✅ OPA Server detected and running")
            else:
                print("⚠️  OPA Server responding but may not be healthy")
        except requests.exceptions.RequestException:
            print("❌ WARNING: OPA Server not detected at localhost:8181")
            print("   Please start OPA before using the application!")
            print("   Command: opa run --server --addr localhost:8181 opa/")
            print()

            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                print("Exiting... Please start OPA server first.")
                sys.exit(1)
    except ImportError:
        print("⚠️  requests library not installed, skipping OPA check")

    print()
    print("🎯 Starting Flask application...")
    print("-" * 70)
    print()

    # Run the application
    try:
        app.run(
            debug=debug_mode,
            host=host,
            port=port,
            threaded=True,
            use_reloader=debug_mode
        )
    except KeyboardInterrupt:
        print()
        print()
        print("=" * 70)
        print("🛑 Shutting down server...")
        print("=" * 70)
        sys.exit(0)
    except Exception as e:
        print()
        print("=" * 70)
        print(f"❌ Error starting server: {e}")
        print("=" * 70)
        sys.exit(1)
