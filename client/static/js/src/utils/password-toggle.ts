/**
 * Password Visibility Toggle Utility
 * 
 * Provides functionality to toggle password field visibility with an eye icon button.
 */

/**
 * Adds a visibility toggle button to a password input field
 * @param passwordInput The password input element to add toggle to
 * @param containerClass Optional CSS class for the wrapper container
 */
export function addPasswordToggle(passwordInput: HTMLInputElement, containerClass: string = 'password-input-wrapper'): void {
    // Check if already wrapped
    if (passwordInput.parentElement?.classList.contains(containerClass)) {
        return; // Already has toggle
    }

    // Create wrapper container
    const wrapper = document.createElement('div');
    wrapper.className = containerClass;
    
    // Insert wrapper before the input
    passwordInput.parentNode?.insertBefore(wrapper, passwordInput);
    
    // Move input into wrapper
    wrapper.appendChild(passwordInput);
    
    // Create toggle button
    const toggleButton = document.createElement('button');
    toggleButton.type = 'button';
    toggleButton.className = 'password-toggle-btn';
    toggleButton.setAttribute('aria-label', 'Toggle password visibility');
    toggleButton.innerHTML = `
        <svg class="eye-icon eye-closed" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
        </svg>
        <svg class="eye-icon eye-open" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: none;">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
    `;
    
    // Add toggle button to wrapper
    wrapper.appendChild(toggleButton);
    
    // Add click handler
    toggleButton.addEventListener('click', (e) => {
        e.preventDefault();
        togglePasswordVisibility(passwordInput, toggleButton);
    });
}

/**
 * Toggles password visibility for a given input
 * @param passwordInput The password input element
 * @param toggleButton The toggle button element
 */
function togglePasswordVisibility(passwordInput: HTMLInputElement, toggleButton: HTMLButtonElement): void {
    const eyeClosed = toggleButton.querySelector('.eye-closed') as SVGElement;
    const eyeOpen = toggleButton.querySelector('.eye-open') as SVGElement;
    
    if (passwordInput.type === 'password') {
        // Show password
        passwordInput.type = 'text';
        eyeClosed.style.display = 'none';
        eyeOpen.style.display = 'block';
        toggleButton.setAttribute('aria-label', 'Hide password');
    } else {
        // Hide password
        passwordInput.type = 'password';
        eyeClosed.style.display = 'block';
        eyeOpen.style.display = 'none';
        toggleButton.setAttribute('aria-label', 'Show password');
    }
}

/**
 * Adds password toggles to all password inputs in a container
 * @param container The container element to search for password inputs
 */
export function addPasswordTogglesInContainer(container: HTMLElement): void {
    const passwordInputs = container.querySelectorAll('input[type="password"]') as NodeListOf<HTMLInputElement>;
    passwordInputs.forEach(input => {
        addPasswordToggle(input);
    });
}

/**
 * Adds password toggles to all password inputs on the page
 */
export function addPasswordTogglesGlobal(): void {
    const passwordInputs = document.querySelectorAll('input[type="password"]') as NodeListOf<HTMLInputElement>;
    passwordInputs.forEach(input => {
        addPasswordToggle(input);
    });
}
