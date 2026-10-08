import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

// Capture-derived strings must only ever be rendered as text: raw HTML injection is banned (SEC-06).
const noRawHtml = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "dangerouslySetInnerHTML is banned: render capture-derived strings as text.",
  },
  {
    selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]",
    message: "innerHTML/outerHTML are banned: render capture-derived strings as text.",
  },
  {
    selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
    message: "insertAdjacentHTML is banned.",
  },
];

export default tseslint.config(
  { ignores: ["dist", "src/api/schema.ts"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["src/**/*.{ts,tsx}", "e2e/**/*.ts"],
    plugins: { react, "react-hooks": reactHooks, "jsx-a11y": jsxA11y },
    languageOptions: { ecmaVersion: 2022 },
    settings: { react: { version: "detect" } },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
      "react/no-danger": "error",
      "react/jsx-no-target-blank": "error",
      "no-restricted-syntax": ["error", ...noRawHtml],
      "no-eval": "error",
      "no-implied-eval": "error",
    },
  },
);
