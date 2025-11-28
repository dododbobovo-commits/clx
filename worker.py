import os
import time
import json
import requests

from segments import SegmentJob, SegmentResult
from collatz import collatz_segment

# адрес узла, к которому стучится воркер (можно переопределить NODE_URL)
NODE_URL = os.environ.get("NODE_URL", "http://127.0.0.1:8000")


def fetch_job():
    try:
        res = requests.get(NODE_URL + "/job", timeout=3)
        data = res.json()
        return data.get("job")
    except Exception:
        return None


def send_result(result: SegmentResult):
    payload = {"result": result.to_dict()}
    try:
        requests.post(NODE_URL + "/result", json=payload, timeout=3)
    except Exception:
        pass


def main():
    print("WORKER started")
    while True:
        job_data = fetch_job()

        if job_data is None:
            time.sleep(0.2)
            continue
        if not job_data or job_data.get("start_value") is None:
            time.sleep(0.2)
            continue

        job = SegmentJob(
            start_value=job_data["start_value"],
            max_steps=job_data["max_steps"],
            job_index=job_data["job_index"],
            expected_prev_hash=job_data["expected_prev_hash"],
            segment_id=job_data["segment_id"],
        )

        values, steps, peak, reached_one = collatz_segment(job.start_value, job.max_steps)

        result = SegmentResult(
            segment_id=job.segment_id,
            values=values,
            steps_done=steps,
            peak=peak,
            reached_one=reached_one,
        )

        send_result(result)


if __name__ == "__main__":
    main()
