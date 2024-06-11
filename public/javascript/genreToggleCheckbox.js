function toggleCheckbox(checkboxId) {
    var checkbox = document.getElementById(checkboxId);
    checkbox.checked = !checkbox.checked;

    var checkboxes = document.querySelectorAll('input[name="genre"]');
    var checked = Array.from(checkboxes).some(checkbox => checkbox.checked);

    var submitButton = document.getElementById('submitButton');
    if (checked) {
        submitButton.classList.remove('favorite-genre-disabled-button');
        submitButton.classList.add('favorite-genre-enabled-button');
        submitButton.disabled = false;
        submitButton.textContent = 'Continue';
    } else {
        submitButton.classList.remove('favorite-genre-enabled-button');
        submitButton.classList.add('favorite-genre-disabled-button');
        submitButton.disabled = true;
        submitButton.textContent = 'Select at least one genre to continue';
    }
}
