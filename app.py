import matplotlib
matplotlib.use('Agg')  # Use the Agg backend for rendering images

import matplotlib.pyplot as plt
from flask import Flask, render_template, request, jsonify, send_file
import io
from simulatorAttacker import Simulator

app = Flask(__name__)

# Global variable to store the simulator instance
simulator = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/rhhh')
def rhhh_info():
    return render_template('rhhh.html')

@app.route('/run_simulation', methods=['POST'])
def run_simulation():
    global simulator
    attack_perc = int(request.form['attack_perc'])
    subs_perc = int(request.form['subs_perc'])
    start_perc = int(request.form['start_perc'])
    pref_size = int(request.form['pref_size'])

    # Initialize the simulator and run the simulation
    simulator = Simulator()
    simulator.simulate_attack(attack_perc, subs_perc, start_perc, pref_size)

    blocked_count = simulator.blocked_stats()
    total_requests = simulator.total_req_stats()
    legit_requests = simulator.legit_req_stats()
    legit_blocked = simulator.legit_block_stats()
    attack_requests = simulator.attack_req_stats()
    attack_blocked = blocked_count - legit_blocked
    perc_attack_blocked = (attack_blocked / attack_requests) * 100 if attack_requests > 0 else 0
    perc_legit_blocked = (legit_blocked / legit_requests) * 100 if legit_requests > 0 else 0

    legit_not_blocked = legit_requests - legit_blocked
    attack_not_blocked = attack_requests - attack_blocked

    # Prepare the results to send back to the frontend
    results = {
        'blocked_count': blocked_count,
        'total_requests': total_requests,
        'legit_requests': legit_requests,
        'legit_blocked': legit_blocked,
        'attack_requests': attack_requests,
        'attack_blocked': attack_blocked,
        'percentage_attack_blocked': perc_attack_blocked,
        'percentage_legit_blocked': perc_legit_blocked,
        'legit_not_blocked': legit_not_blocked,
        'attack_not_blocked': attack_not_blocked
    }
    #generate_load_plot()
    return jsonify(results)
@app.route('/generate_plot')
def generate_plot():
    global simulator
    if simulator is None:
        return "Simulation not run yet.", 400

    # Retrieve values for the first 3 diagrams
    legit_blocked = int(request.args.get('legit_blocked'))
    attack_blocked = int(request.args.get('attack_blocked'))
    perc_legit_blocked = float(request.args.get('perc_legit_blocked'))
    perc_attack_blocked = float(request.args.get('perc_attack_blocked'))
    total_requests = int(request.args.get('total_requests'))
    blocked_count = int(request.args.get('blocked_count'))
    legit_not_blocked = int(request.args.get('legit_not_blocked'))
    attack_not_blocked = int(request.args.get('attack_not_blocked'))

    # Prepare the data for the 4th diagram (Packets vs Ticks)
    load_data = simulator.get_load()  # Get load data from simulator
    ticks = list(load_data.keys())    # Ticks
    packets = list(load_data.values())  # Number of Packets

    # Create a 2x2 figure with 4 subplots
    fig, ax = plt.subplots(2, 2, figsize=(18, 12))  # Create 4 subplots

    # First chart: Blocked vs Legitimate Blocked
    labels = ['Legitimate Requests Blocked', 'Attack Requests Blocked']
    values = [legit_blocked, attack_blocked]
    percentages = [perc_legit_blocked, perc_attack_blocked]

    bars = ax[0, 0].bar(labels, values, color=['#007bff', '#dc3545'])
    for bar, percentage in zip(bars, percentages):
        height = bar.get_height()
        ax[0, 0].annotate(f'{percentage:.2f}%',
                          xy=(bar.get_x() + bar.get_width() / 2, height),
                          xytext=(0, 3),
                          textcoords="offset points",
                          ha='center', va='bottom')
    ax[0, 0].set_ylabel('Number of Requests Blocked')
    ax[0, 0].set_title('Blocked Requests Comparison')

    # Second chart: Total Blocked vs Non-blocked
    total_non_blocked = total_requests - blocked_count
    labels_2 = ['Blocked Requests', 'Non-blocked Requests']
    values_2 = [blocked_count, total_non_blocked]
    ax[0, 1].pie(values_2, labels=labels_2, autopct='%1.1f%%', colors=['#ff5733', '#33c1ff'])
    ax[0, 1].set_title('Total Blocked vs Non-blocked Requests')

    # Third chart: Legitimate Not Blocked vs Attack Not Blocked
    labels_3 = ['Legitimate Not Blocked', 'Attack Not Blocked']
    values_3 = [legit_not_blocked, attack_not_blocked]
    ax[1, 0].bar(labels_3, values_3, color=['#28a745', '#ffc107'])
    ax[1, 0].set_ylabel('Number of Non-blocked Requests')
    ax[1, 0].set_title('Legitimate vs Attack Non-blocked Requests')

    # Fourth chart: Packets vs Ticks (New Diagram)
    ax[1, 1].plot(ticks, packets, marker='o', linestyle='-', color='b')
    ax[1, 1].set_xlabel('Ticks')
    ax[1, 1].set_ylabel('Number of Packets')
    ax[1, 1].set_title('Packets as a function of Ticks')

    # Save the plot as an image
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plt.close(fig)  # Close the figure to free up memory

    return send_file(img, mimetype='image/png')

#
# @app.route('/generate_load_plot')
# def generate_load_plot():
#     global simulator
#     if simulator is None:
#         return "Simulation not run yet.", 400
#
#     # Get the load data (ticks vs packets)
#     load_data = simulator.get_load()
#
#     # Ensure there is data to plot
#     if not load_data:
#         return "No data available for plotting.", 400
#
#     # Prepare the data for plotting
#     ticks = list(load_data.keys())
#     packets = list(load_data.values())
#
#     # Create the plot for Packets vs Ticks
#     fig, ax = plt.subplots()
#     ax.plot(ticks, packets, marker='o', linestyle='-', color='b')
#     ax.set_xlabel('Ticks')
#     ax.set_ylabel('Number of Packets')
#     ax.set_title('Packets as a function of Ticks')
#
#     # Save the plot as an image
#     img = io.BytesIO()
#     plt.savefig(img, format='png')
#     img.seek(0)
#
#     return send_file(img, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True)
