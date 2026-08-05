import type { PolicyValues } from "../types";

const TIERS = [0, 8, 16, 24, 32];
const format = (value: bigint) => new Intl.NumberFormat("en-US").format(value);
export function QuotePreview({ policy }: { policy: PolicyValues }) {
  let base = 0n,
    rounds = 0;
  try {
    base = BigInt(policy.base_iterations);
    rounds = policy.base_render_rounds;
  } catch {}
  return (
    <section className="quote-preview" aria-labelledby="quote-title">
      <h2 id="quote-title">Signed quote preview</h2>
      <p>The immutable work Shar promises at representative pressure tiers.</p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Pressure tier</th>
              <th>Time-lock iterations</th>
              <th>Rendering rounds</th>
            </tr>
          </thead>
          <tbody>
            {TIERS.map((tier) => (
              <tr key={tier}>
                <th>Tier {tier}</th>
                <td>{base > 0n ? format(base << BigInt(tier)) : "—"}</td>
                <td>
                  {rounds > 0
                    ? new Intl.NumberFormat("en-US").format(
                        rounds * 2 ** Math.min(tier, 8),
                      )
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
