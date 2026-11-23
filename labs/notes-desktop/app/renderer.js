// notes-desktop renderer (lab app): draws the note list.

// D8: note titles are written into the page as markup.
function renderList(notes) {
  const list = document.getElementById("notes");
  list.innerHTML = notes.map((n) => `<li>${n.title}</li>`).join("");
}

// Look-alike: the same list built from text nodes.
function renderListSafe(notes) {
  const list = document.getElementById("notes");
  list.replaceChildren(...notes.map((n) => {
    const item = document.createElement("li");
    item.textContent = n.title;
    return item;
  }));
}

window.notes.list().then((notes) => (notes.length > 100 ? renderListSafe(notes) : renderList(notes)));
