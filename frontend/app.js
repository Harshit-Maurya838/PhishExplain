document.addEventListener('DOMContentLoaded', () => {
    const emailInput = document.getElementById('emailInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = analyzeBtn.querySelector('span');
    const loader = analyzeBtn.querySelector('.loader');
    
    const resultsSection = document.getElementById('resultsSection');
    
    // UI Elements
    const riskLevelBadge = document.getElementById('riskLevelBadge');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreText = document.getElementById('scoreText');
    const scoreDescription = document.getElementById('scoreDescription');
    const scoreBreakdown = document.getElementById('scoreBreakdown');
    const aiScoreBar = document.getElementById('aiScoreBar');
    const aiScoreVal = document.getElementById('aiScoreVal');
    const heuristicScoreBar = document.getElementById('heuristicScoreBar');
    const heuristicScoreVal = document.getElementById('heuristicScoreVal');
    const threatSummaryBox = document.getElementById('threatSummaryBox');
    const threatSummaryText = document.getElementById('threatSummaryText');
    const flagsContainer = document.getElementById('flagsContainer');
    const highlightedTextContainer = document.getElementById('highlightedText');
    const noFlagsMessage = document.getElementById('noFlagsMessage');

    analyzeBtn.addEventListener('click', async () => {
        const text = emailInput.value.trim();
        if (!text) {
            alert('Please paste some text to analyze.');
            return;
        }

        // Set loading state
        btnText.classList.add('hidden');
        loader.classList.remove('hidden');
        analyzeBtn.disabled = true;

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ content: text })
            });

            if (!response.ok) {
                throw new Error('Analysis failed');
            }

            const data = await response.json();
            renderResults(data);
            
            // Show results section
            resultsSection.classList.remove('hidden');
            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth' });

        } catch (error) {
            console.error('Error during analysis:', error);
            alert('An error occurred during analysis. Make sure the backend is running.');
        } finally {
            // Reset loading state
            btnText.classList.remove('hidden');
            loader.classList.add('hidden');
            analyzeBtn.disabled = false;
        }
    });

    function renderResults(data) {
        // 1. Update Score Ring
        const score = data.final_score;
        scoreText.textContent = Math.round(score);
        scoreCircle.setAttribute('stroke-dasharray', `${score}, 100`);
        
        // Remove old classes
        scoreCircle.classList.remove('low', 'medium', 'high');
        riskLevelBadge.classList.remove('low', 'medium', 'high');
        
        const levelLower = data.risk_level.toLowerCase();
        scoreCircle.classList.add(levelLower);
        riskLevelBadge.classList.add(levelLower);
        riskLevelBadge.textContent = `${data.risk_level} Risk`;

        // 2. Show analysis complete description
        scoreDescription.textContent = 'Analysis complete. Review the highlighted flags below.';
        scoreDescription.classList.remove('hidden');

        // 3. Score breakdown bars (AI + Heuristic)
        const aiPct = Math.round(data.ai_score);
        const hPct = Math.min(Math.round(data.heuristic_score), 100);
        aiScoreVal.textContent = aiPct;
        heuristicScoreVal.textContent = hPct;
        setTimeout(() => {
            aiScoreBar.style.width = `${aiPct}%`;
            heuristicScoreBar.style.width = `${hPct}%`;
        }, 50);
        scoreBreakdown.classList.remove('hidden');

        // 4. Insert Highlighted HTML & Threat Summary
        highlightedTextContainer.innerHTML = data.highlighted_html;
        
        if (data.summary) {
            threatSummaryBox.classList.remove('hidden');
            threatSummaryText.textContent = data.summary;
        } else {
            threatSummaryBox.classList.add('hidden');
        }

        // 5. Render Explanations
        flagsContainer.innerHTML = '';
        
        if (data.flags && data.flags.length > 0) {
            noFlagsMessage.classList.add('hidden');
            
            data.flags.forEach(flag => {
                const flagEl = document.createElement('div');
                
                // Map type to a basic CSS class modifier prefix
                let typeClass = '';
                if(flag.type.includes('Urgency')) typeClass = 'type-ur';
                else if(flag.type.includes('Credential')) typeClass = 'type-cr';
                else if(flag.type.includes('Fear') || flag.type.includes('Authority')) typeClass = 'type-fe';
                else if(flag.type.includes('Financial')) typeClass = 'type-fb';
                else if(flag.type.includes('URL') || flag.type.includes('Short') || flag.type.includes('Domain') || flag.type.includes('Homograph')) typeClass = 'type-sus';
                else typeClass = 'type-def';

                flagEl.className = `flag-item ${typeClass}`;
                
                flagEl.innerHTML = `
                    <div class="flag-header">
                        <h4>${flag.type}</h4>
                        <span class="flag-score">+${flag.score} risk &bull; ${Math.round(flag.confidence * 100)}% confidence</span>
                    </div>
                    <div class="flag-match">&ldquo;${flag.matched_text}&rdquo;</div>
                    <div class="flag-details">
                        <div class="detail-row">
                            <span class="detail-label">Tactics</span>
                            <p class="flag-explanation">${flag.explanation || 'Suspicious indicator found.'}</p>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Attacker Goal</span>
                            <p class="flag-gain">${flag.attacker_gain || 'Potential compromise.'}</p>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Safe Action</span>
                            <p class="flag-verify">${flag.how_to_verify || 'Proceed with caution.'}</p>
                        </div>
                    </div>
                `;
                flagsContainer.appendChild(flagEl);
            });
        } else {
            noFlagsMessage.classList.remove('hidden');
        }
    }
});
