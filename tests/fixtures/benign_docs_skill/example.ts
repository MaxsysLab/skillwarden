// Benign TypeScript: generics and standard env access must not trip the scanner.
async function getUser(id: string): Promise<User> {
  const token = process.env.GITHUB_TOKEN;
  return fetchUser(id, token);
}

function render(items: Array<System>): void {
  console.log(items.length);
}
