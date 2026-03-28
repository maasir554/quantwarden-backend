import argparse
import uvicorn


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start OneForAll FastAPI server")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8002,
        help="Port to run the API server on (default: 8002)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(f"Starting API server at http://localhost:{args.port}")
    print(f"OpenAPI docs: http://localhost:{args.port}/docs")
    uvicorn.run("fastapi_app.main:app", host="0.0.0.0", port=args.port, reload=False)
