let isGenerating = false;

$("#doc-generator").submit(function(e) {
    e.preventDefault();
    if (isGenerating) return;

    const code = $("#code").val().trim();
    const language = $("#language").val();
    const maxLength = $("#max_length").val();

    if (!language || !code) {
        $("#error-container").html('<div class="error-message">Please fill all fields</div>');
        return;
    }

    isGenerating = true;
    $("#loading-indicator").show();
    $("#submit-btn").prop('disabled', true);
    $("#error-container").empty();

    // Append user message
    $("#chat-container").append(`
        <div class="message user-message">
            <pre><code class="language-${language}">${code}</code></pre>
        </div>
    `);
    Prism.highlightAll(); // Highlight syntax

    // Scroll to bottom
    $("#chat-container").scrollTop($("#chat-container")[0].scrollHeight);

    $.ajax({
        url: "/generate-docs/",
        method: "POST",
        contentType: "application/json",
        data: JSON.stringify({ 
            language, 
            code, 
            max_length: parseInt(maxLength)
        }),
        success: response => {
            if (response.documentation) {
                // Append bot message with generated documentation
                $("#chat-container").append(`
                    <div class="message bot-message">
                        <pre>${response.documentation}</pre>
                    </div>
                `);
            } else {
                // Handle unexpected response format
                $("#error-container").html('<div class="error-message">Unexpected response format</div>');
            }
        },
        error: xhr => {
            const error = xhr.responseJSON?.error || "Generation failed";
            $("#error-container").html(`<div class="error-message">${error}</div>`);
        },
        complete: () => {
            isGenerating = false;
            $("#loading-indicator").hide();
            $("#submit-btn").prop('disabled', false);
            $("#chat-container").scrollTop($("#chat-container")[0].scrollHeight);
        }
    });
});