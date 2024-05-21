document.addEventListener("DOMContentLoaded", function() {
    var showMoreLinks = document.querySelectorAll(".show-more-link");

    showMoreLinks.forEach(function(link) {
        link.addEventListener("click", function(event) {
            event.preventDefault();
            var bookId = this.getAttribute("data-book-id");
            var descriptionContainer = document.getElementById("description-container-" + bookId);

            fetch(`/book/${bookId}`)
                .then(response => response.json())
                .then(data => {
                    // Replace the short description with the full description
                    descriptionContainer.innerHTML = `<p class="mb-2 full-description">${data.description}</p>`;
                })
                .catch(error => console.error('Error fetching book description:', error));
        });
    });
});
