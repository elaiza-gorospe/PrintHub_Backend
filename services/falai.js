/**
 * fal.ai integration helper
 * Uses the synchronous /fal.run endpoint.
 * FAL_KEY format: <key-id>:<key-secret>
 */

const FAL_BASE = "https://fal.run";
const DEFAULT_MODEL = "fal-ai/flux/dev";

/**
 * Generate an image from a text prompt.
 * @param {Object} opts
 * @param {string} opts.prompt
 * @param {string} [opts.model]
 * @param {"square_hd"|"square"|"portrait_4_3"|"portrait_16_9"|"landscape_4_3"|"landscape_16_9"} [opts.imageSize]
 * @param {number} [opts.numSteps]
 * @returns {Promise<{url: string, width: number, height: number, seed: number}>}
 */
async function generateImage({
  prompt,
  model = DEFAULT_MODEL,
  imageSize = "square_hd",
  numSteps = 28,
}) {
  const falKey = process.env.FAL_KEY;
  if (!falKey) throw new Error("FAL_KEY environment variable is not set");

  const url = `${FAL_BASE}/${model}`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Key ${falKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      prompt,
      image_size: imageSize,
      num_inference_steps: numSteps,
      guidance_scale: 3.5,
      num_images: 1,
      safety_tolerance: "2",
      output_format: "jpeg",
    }),
  });

  if (!res.ok) {
    let errMsg = `fal.ai error: ${res.status}`;
    try {
      const errBody = await res.json();
      errMsg = errBody?.message || errBody?.detail || errMsg;
    } catch {
      /* ignore */
    }
    throw new Error(errMsg);
  }

  const data = await res.json();

  const image = data?.images?.[0];
  if (!image?.url) throw new Error("fal.ai returned no image URL");

  return {
    url: image.url,
    width: image.width,
    height: image.height,
    seed: data.seed ?? null,
  };
}

module.exports = { generateImage };
