function formatDate(dateString) {
    const date = new Date(dateString);
    
    const options = {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    };
    const formattedDate = date.toLocaleDateString('en-US', options);
    return formattedDate;
}

export default formatDate;
