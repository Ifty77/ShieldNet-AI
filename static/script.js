// Navigate to security check
function navigateToHome() {
    window.location.href = "/home";
}

// Smooth scroll to "How It Works" section
function scrollToHowItWorks() {
    const howItWorksSection = document.querySelector('.how-it-works');
    if (howItWorksSection) {
        howItWorksSection.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

// Analyze the request
async function analyzeRequest() {
    const inputField = document.getElementById("requestInput");
    const resultBox = document.getElementById("resultBox");

    if (!inputField || !resultBox) {
        console.error("Missing requestInput or resultBox element in HTML.");
        return;
    }

    const userRequest = inputField.value.trim();

    if (!userRequest) {
        resultBox.innerHTML = `
            <div class="result-card error">
                <h3>⚠ No Input Provided</h3>
                <p>Please enter a URL or request before checking.</p>
            </div>
        `;
        return;
    }

    resultBox.innerHTML = `
        <div class="result-card scanning">
            <h3>🔍 Analyzing Request...</h3>
            <p>Please wait while ShieldNet AI checks for threats.</p>
        </div>
    `;

    try {
        const response = await fetch("/check_request", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                user_request: userRequest,
                uri: userRequest,
                get_data: "",
                post_data: ""
            })
        });

        const result = await response.json();

        if (result.status === "valid") {
            resultBox.innerHTML = `
                <div class="result-card safe">
                    <h3>✅ All Clear!</h3>
                    <p>${result.message}</p>
                    ${
                        result.redirect_url
                            ? `<p>Redirecting you to the safe website in 2 seconds...</p>`
                            : ``
                    }
                </div>
            `;

            if (result.redirect_url) {
                setTimeout(() => {
                    window.location.href = result.redirect_url;
                }, 2000);
            }
        } else if (result.status === "malicious") {
            resultBox.innerHTML = `
                <div class="result-card malicious">
                    <h3>🚨 Threat Detected</h3>
                    <p>${result.message}</p>
                    ${
                        result.signature_category
                            ? `<p><strong>Detected Type:</strong> ${result.signature_category}</p>`
                            : ``
                    }
                </div>
            `;
        } else {
            resultBox.innerHTML = `
                <div class="result-card error">
                    <h3>⚠ Unexpected Response</h3>
                    <p>${result.message || "Something went wrong."}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error("Error:", error);
        resultBox.innerHTML = `
            <div class="result-card error">
                <h3>❌ Request Failed</h3>
                <p>Could not connect to the server. Please try again.</p>
            </div>
        `;
    }
}