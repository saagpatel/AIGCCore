module.exports = {
  extends: ["stylelint-config-standard"],
  ignoreFiles: ["**/*.{js,jsx,ts,tsx}"],
  rules: {
    "at-rule-no-unknown": [
      true,
      {
        ignoreAtRules: [
          "tailwind",
          "apply",
          "layer",
          "config",
          "theme",
          "utility",
          "variant",
          "custom-variant",
        ],
      },
    ],
    "color-function-alias-notation": null,
    "color-function-notation": null,
    "alpha-value-notation": null,
    "selector-class-pattern": null,
    "media-feature-range-notation": null,
    "custom-property-empty-line-before": null,
    "font-family-name-quotes": null,
    "shorthand-property-no-redundant-values": null
  },
};
