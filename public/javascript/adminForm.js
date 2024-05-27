const form = document.getElementById('admin-panel');

const submitButton = document.getElementById('submitButton');

form.addEventListener('submit', function(event) {
    // Trigger TinyMCE to save content to the textarea
    tinymce.triggerSave();
    
    // Check if the textarea is empty
    const description = document.getElementById('description').value;
    console.log(description)
    if (!description.trim()) {
        event.preventDefault();
        alert('Please fill in the required field.');
    }
});