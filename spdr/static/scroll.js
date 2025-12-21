    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');

    //let text = "This is some long text that will scroll vertically on the canvas.";
    let text = "";
    let yPos = 20; //canvas.height; // Start below the canvas
    const scrollSpeed = 1; // Pixels per frame
    const lineHeight = 25; // Adjust based on your font size

     async function fetchRemoteText(url) {
     try {
        const response = await fetch(url);

    	// Check if the request was successful
    	if (!response.ok) {
      		throw new Error(`HTTP error! status: ${response.status}`);
    	}

    	// Get the response as plain text
    	const textContent = await response.text();
    	return textContent;

       } catch (error) {
        console.error("Error fetching remote text:", error);
        return null;
      }

     }

    function sleep(ms) {
  	return new Promise(resolve => setTimeout(resolve, ms));
    }

    async function animateScroll() {
        // Clear the canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Set text properties
        ctx.font = '16px Arial';
        ctx.fillStyle = 'black';
        ctx.textAlign = 'center';
	let currentY = yPos;

	const websiteUrl = "http://localhost:8080/scrollbuffer"; 
	fetchRemoteText(websiteUrl)
	  .then(text => {
	   	if (text) {
			const dnsevents = text.split(';');
			for(let x=0;x<dnsevents.length;x++){
				ctx.fillText(dnsevents[x], canvas.width/2, currentY);
				//console.log(dnsevents[x]);
			        currentY += lineHeight;
			}
			currentY += lineHeight;

    	   	} else {
      		      	console.log("Failed to fetch text content.");
    		}
  	});

	await sleep(3000); //sleep 1 second

	requestAnimationFrame(animateScroll);
	
    }

    // Start the animation
    animateScroll();
