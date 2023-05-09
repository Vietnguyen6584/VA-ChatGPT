document.addEventListener('DOMContentLoaded', () => {
  // Get user data from HTML data attribute
  const usersData = JSON.parse(document.getElementById('users_data').getAttribute('data-users'));

  // Create table rows and cells
  const tableBody = document.querySelector('tbody');
  usersData.forEach((user) => {
      const row = tableBody.insertRow(-1);
      const roles = {
        1: 'Admin',
        2: 'Moderator',
        3: 'User',
        4: 'Banned',
        5: 'Disabled',
        else: 'Unknown'
      };
      row.insertCell(0).innerHTML = user['id'];
      row.insertCell(1).innerHTML = `<a href="/user/${user['id']}">${user['username']}</a>`;
      row.insertCell(2).innerHTML = user['email'];
      const roleCell = row.insertCell(3);
      roleCell.innerHTML = roles[user['role']];
      const actionsCell = row.insertCell(4);
      actionsCell.innerHTML = `
          <a href="/user/${user['id']}"><button class="view-button" data-user-id="${user['id']}"><i class="fa  fa-cogs"></i></button></a>
          <button class="delete-button" data-user-id="${user['id']}"><i class="fa fa-trash"></i></button>
      `;
      const deleteButton = actionsCell.querySelector('.delete-button');
      deleteButton.addEventListener('click', () => {
          const userId = deleteButton.getAttribute('data-user-id');
          const xhr = new XMLHttpRequest();
          xhr.open('DELETE', `/removeuser/${userId}`);
          xhr.onload = () => {
              if (xhr.status === 200) {
                  location.reload();
              } else {
                  console.log('Failed to delete user.');
              }
          };
          xhr.send();
      });
  });
});
