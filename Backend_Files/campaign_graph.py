import networkx as nx
import matplotlib.pyplot as plt


def generate_campaign_graph(domain, emails):
    G = nx.Graph()

    G.add_node(domain)

    for email in emails:
        sender = email["sender"]

        G.add_node(sender)
        G.add_edge(sender, domain)

    filename = f"{domain}_campaign.png"

    plt.figure(figsize=(8, 6))
    nx.draw(G, with_labels=True)

    plt.savefig(filename)
    plt.close()

    return filename

if __name__ == "__main__":
    emails = [
        {"sender": "attacker@test.com"},
        {"sender": "verify@test.com"},
        {"sender": "security@test.com"}
    ]

    file = generate_campaign_graph(
        "test.com",
        emails
    )

    print(file)