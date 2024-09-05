from flask import Flask, render_template, request, jsonify
from simulatorAttacker import Simulator  # Import the simulator from your code
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # Render the UI page

@app.route('/rhhh')
def rhhh_info():
    return render_template('rhhh.html')  # Render the RHHH information page
@app.route('/run_simulation', methods=['POST'])
def run_simulation():
    # Get parameters from the form
    attack_perc = int(request.form['attack_perc'])
    subs_perc = int(request.form['subs_perc'])
    start_perc = int(request.form['start_perc'])
    pref_size = int(request.form['pref_size'])

    # Initialize and run the simulator
    simulator = Simulator()
    simulator.simulate_attack(attack_perc, subs_perc, start_perc, pref_size)

    # Collect statistics from the simulation
    blocked_count = simulator.blocked_stats()
    total_requests = simulator.total_req_stats()
    legit_blocked = simulator.legit_block_stats()
    attack_blocked = simulator.attack_block_stats()
    attack_requests = simulator.attack_req_stats()

    # Calculate the percentages
    percentage_attack_blocked = (attack_blocked / attack_requests) * 100 if attack_requests > 0 else 0
    percentage_legit_blocked = (legit_blocked / simulator.legit_req_stats()) * 100 if simulator.legit_req_stats() > 0 else 0

    # Prepare the results to send back to the frontend
    results = {
        'blocked_count': blocked_count,
        'total_requests': total_requests,
        'legit_blocked': legit_blocked,
        'attack_requests': attack_requests,
        'attack_blocked': attack_blocked,
        'percentage_attack_blocked': percentage_attack_blocked,
        'percentage_legit_blocked': percentage_legit_blocked
    }

    return jsonify(results)  # Return the results as JSON to the frontend


if __name__ == '__main__':
    app.run(debug=True)
