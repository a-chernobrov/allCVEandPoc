document.addEventListener('DOMContentLoaded', function() {
    const tableBody = document.querySelector('#cve-table tbody');
    const prevPageButton = document.getElementById('prev-page');
    const nextPageButton = document.getElementById('next-page');
    const pageInfo = document.getElementById('page-info');
    const searchInput = document.getElementById('search-input');
    const addButton = document.getElementById('add-button');
    const addModal = document.getElementById('add-modal');
    const addCveForm = document.getElementById('add-cve-form');
    const closeAddButton = document.querySelector('.close-add-button');

    const modal = document.getElementById('modal');
    const closeButton = document.querySelector('.close-button');
    const modalCveId = document.getElementById('modal-cve-id');
    const detailsContent = document.getElementById('details-content');
    const modalCveLinks = document.getElementById('modal-cve-links');

    let currentPage = 1;
    const rowsPerPage = 100;
    let currentSearch = '';

    function fetchTotalCve() {
        fetch('/api/cve/total')
            .then(response => response.json())
            .then(data => {
                const totalCveElement = document.getElementById('total-cve');
                if (totalCveElement) {
                    totalCveElement.textContent = `Total CVEs in database: ${data.total}`;
                }
            })
            .catch(error => console.error('Error fetching total CVE count:', error));
    }

    function fetchData(page, search = '') {
        const url = new URL('/api/cve', window.location.origin);
        url.searchParams.append('page', page);
        url.searchParams.append('limit', rowsPerPage);
        if (search) {
            url.searchParams.append('search', search);
        }

        fetch(url)
            .then(response => response.json())
            .then(data => {
                displayTable(data.data);
                setupPagination(data.total_records, data.page, data.limit);
            })
            .catch(error => console.error('Error fetching CVE data:', error));
    }

    function displayTable(data) {
        tableBody.innerHTML = '';
        data.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${item.year}</td>
                <td>${item.cve_id}</td>
                <td>${item.description}</td>
                <td>${item.links_count}</td>
                <td><button class="details-btn" data-cve-id="${item.cve_id}">Details</button></td>
            `;
            tableBody.appendChild(row);
        });

        document.querySelectorAll('.details-btn').forEach(button => {
            button.addEventListener('click', function() {
                const cveId = this.getAttribute('data-cve-id');
                fetchCveDetails(cveId);
            });
        });
    }

    function fetchCveDetails(cveId) {
        fetch(`/api/cve/${cveId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json(); // Expect JSON response
            })
            .then(data => {
                modalCveId.textContent = cveId;
                
                // Format the details into HTML
                let htmlContent = `<p><strong>Description:</strong> ${data.description}</p>`;
                if (data.links && data.links.length > 0) {
                    htmlContent += '<p><strong>Links:</strong></p><ul>';
                    data.links.forEach(link => {
                        htmlContent += `<li><a href="${link}" target="_blank">${link}</a></li>`;
                    });
                    htmlContent += '</ul>';
                } else {
                    htmlContent += '<p><strong>Links:</strong> No links available.</p>';
                }
                
                detailsContent.innerHTML = htmlContent;
                modal.style.display = 'block';
            })
            .catch(error => {
                console.error('Error fetching CVE details:', error);
                modalCveId.textContent = cveId;
                detailsContent.innerHTML = '<p>Error fetching details. Please try again later.</p>';
                modal.style.display = 'block';
            });
    }

    function setupPagination(totalRecords, page, limit) {
        const pageCount = Math.ceil(totalRecords / limit);
        pageInfo.textContent = `Page ${page} of ${pageCount}`;

        prevPageButton.disabled = page === 1;
        nextPageButton.disabled = page === pageCount;
    }

    prevPageButton.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            fetchData(currentPage, currentSearch);
        }
    });

    nextPageButton.addEventListener('click', () => {
        currentPage++;
        fetchData(currentPage, currentSearch);
    });

    searchInput.addEventListener('input', () => {
        currentSearch = searchInput.value;
        currentPage = 1;
        fetchData(currentPage, currentSearch);
    });

    closeButton.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    window.addEventListener('click', (event) => {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
        if (event.target == addModal) {
            addModal.style.display = 'none';
        }
    });

    addButton.addEventListener('click', () => {
        addModal.style.display = 'block';
    });

    closeAddButton.addEventListener('click', () => {
        addModal.style.display = 'none';
    });

    addCveForm.addEventListener('submit', function(event) {
        event.preventDefault();
        
        const cve_id = document.getElementById('cve-id-input').value;
        const year = document.getElementById('year-input').value;
        const description = document.getElementById('description-input').value;
        const links = document.getElementById('links-input').value.split(',').map(link => link.trim());

        const data = {
            cve_id,
            year,
            description,
            links
        };

        fetch('/api/cve', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
        .then(response => response.json())
        .then(result => {
            console.log('Success:', result);
            addModal.style.display = 'none';
            fetchData(currentPage, currentSearch); // Refresh the table
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    // Initial fetch
    fetchData(currentPage);
    fetchTotalCve();
});
