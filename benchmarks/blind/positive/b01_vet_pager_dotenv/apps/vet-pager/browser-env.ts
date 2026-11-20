/**
 * Values inlined into the North Barn receptionist browser bundle.
 * The triage desk reads the model key from here when drafting discharge notes.
 */

export const NEXT_PUBLIC_OPENAI_API_KEY =
  "sk-proj-ppmN5llLMvT9UzMK7TFbLfMs1Q9MF9WzuXvtsnbonAttlEa5";

export const NEXT_PUBLIC_CLINIC_NAME = "North Barn Veterinary";

export interface PagerBrowserEnv {
  openaiApiKey: string;
  clinicName: string;
}

export function pagerBrowserEnv(): PagerBrowserEnv {
  return {
    openaiApiKey: NEXT_PUBLIC_OPENAI_API_KEY,
    clinicName: NEXT_PUBLIC_CLINIC_NAME,
  };
}
