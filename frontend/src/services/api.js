export async function analyzeCode(filename, code) {
  const response = await fetch("/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filename,
      code,
    }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.detail || "Analysis failed");
  }

  return data;
}
