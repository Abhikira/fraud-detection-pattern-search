document.querySelectorAll("[data-password-target]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.passwordTarget);
    if (!input) {
      return;
    }

    const visible = input.type === "password";
    const label = visible ? "Hide password" : "Show password";
    input.type = visible ? "text" : "password";
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.setAttribute("aria-pressed", String(visible));
    button.querySelector(".eye-icon").hidden = visible;
    button.querySelector(".eye-off-icon").hidden = !visible;
  });
});
