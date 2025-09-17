from app import app
import os

if __name__ == '__main__':
    # Configure for local server accessible from internet
    port = int(os.environ.get('PORT', 5000))

    # Use 0.0.0.0 to accept connections from any IP
    # This allows access from internet when port forwarding is configured
    app.run(host='0.0.0.0', port=port, debug=False)