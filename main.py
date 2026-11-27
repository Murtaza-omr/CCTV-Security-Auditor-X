from app.server import app
import argparse
import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CCTV Security Auditor X")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    print(f"CCTV Security Auditor X: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)
