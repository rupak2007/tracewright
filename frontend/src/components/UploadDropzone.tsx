import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ApiError, queryKeys, uploadCapture } from "../api/client";

/** Drop or choose a PCAP/PCAPNG. The server validates the bytes; the browser only offers a hint. */
export function UploadDropzone() {
  const input = useRef<HTMLInputElement | null>(null);
  const labelId = useId();
  const [over, setOver] = useState(false);
  const client = useQueryClient();
  const navigate = useNavigate();
  const upload = useMutation({
    mutationFn: uploadCapture,
    onSuccess: (r) => {
      void client.invalidateQueries({ queryKey: queryKeys.investigations });
      navigate(`/investigations/${r.id}`);
    },
  });
  const pick = (file: File | undefined) => {
    if (file) upload.mutate(file);
  };
  return (
    <section className="card" aria-labelledby={labelId}>
      <h2 id={labelId}>Upload a capture</h2>
      <div
        className={`dropzone${over ? " over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          pick(e.dataTransfer.files[0]);
        }}
      >
        <p>Drag a .pcap or .pcapng file here, or</p>
        <label className="button">
          Choose a capture file
          <input
            ref={input}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={(e) => pick(e.target.files?.[0])}
          />
        </label>
        <p className="muted">
          Captures are parsed only inside the isolated worker. Compressed files are rejected; analysis
          runs fully offline.
        </p>
      </div>
      <div role="status" aria-live="polite">
        {upload.isPending ? <p>Uploading and validating…</p> : null}
        {upload.isError ? (
          <p className="error">
            {upload.error instanceof ApiError
              ? `${upload.error.code}: ${upload.error.message}`
              : "The upload failed."}
          </p>
        ) : null}
      </div>
    </section>
  );
}
