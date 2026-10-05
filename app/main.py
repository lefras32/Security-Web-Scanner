import logging
from fastapi import FastAPI, HTTPException, status
from app.schemas import ScanRequest, ScanResponse
from app.scanner import (
    ScanRequestError,
    ScanTimeoutError,
    UnsafeTargetError,
    scan_headers,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Security Web Scanner", 
    version="1.0.0",
    description="API for scanning HTTP security headers of a given URL. by lefras32"  
)

@app.post(
    "/scan", 
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan target URL security headers",
    responses={
        400: {"description": "The target URL is unsafe or unsupported"},
        422: {"description": "The request URL is invalid"},
        502: {"description": "Unable to connect to the target server"},
        504: {"description": "The target server timed out"},
    }
)
async def scan_target(payload: ScanRequest):
    target_url = str(payload.url)
    target_host = payload.url.host
    logger.info("Initiating scan for host: %s", target_host)

    try:
        result = await scan_headers(target_url)
    except UnsafeTargetError as err:
        logger.warning("Blocked unsafe scan target host: %s", target_host)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err
    except ScanTimeoutError as err:
        logger.warning("Scan timed out for host: %s", target_host)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(err),
        ) from err
    except ScanRequestError as err:
        logger.warning("Scan request failed for host: %s", target_host)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(err),
        ) from err
    except Exception:
        logger.exception("Unexpected error scanning host: %s", target_host)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred while processing the request.",
        ) from None

    return ScanResponse(
        target_url=target_url,
        security_score=result.security_score,
        headers_found=result.headers_found,
        headers_missing=result.headers_missing,
        recommendations=result.recommendations,
    )
