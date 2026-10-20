// Pipeline: PayPal webhook -> receiver -> risk scoring -> LLM triage -> action -> dashboard
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <deque>
#include <mutex>
#include <string>
#include <sstream>
#include <cstdint>
#include <optional>
#include <charconv>
#include <ctime>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// 1. DATA MODEL
// ---------------------------------------------------------------------------
enum class VerifyResult
{
    RESULT_ERROR,
    RESULT_VERIFIED,
    RESULT_REJECTED
};

enum class AIDecision
{
    NONE,
    APPROVE,
    HOLD,
    REFUND
};

struct TxnRecord 
{
    std::string event_id{};
    std::string event_type{};
    std::string capture_id{};
    std::string order_id{};
    int64_t amount_cents{0};
    std::string currency{};
    std::string status{};
    std::string create_time{};

    int risk_score{0};
    std::vector<std::string> reasons{};
    AIDecision ai_decision{AIDecision::NONE};
    std::string ai_explanation{};
    std::string action_taken{};
    std::string received_at{};
};

struct Token 
{
    std::string value{};
    std::chrono::steady_clock::time_point expires_at{}; //time till expiry
    std::mutex mtx{};
};

// ---------------------------------------------------------------------------
// 2. SHARED STATE
// TODO: where do transactions live? (in-memory deque, SQLite, file log?)
// TODO: who reads/writes it, and from which threads? Protect accordingly.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3. PAYPAL CLIENT
// ---------------------------------------------------------------------------
static std::string get_env_or_empty(const char* name)
{
    const char* v = std::getenv(name);
    return v ? v : "";
}

std::string get_access_token() 
{   
    static Token token;

    {
        std::lock_guard lock(token.mtx);
        if(token.expires_at - std::chrono::steady_clock::now() > std::chrono::seconds(60))
        {           
            std::cout << "Using token that expires at " << std::chrono::duration_cast<std::chrono::seconds>(token.expires_at - std::chrono::steady_clock::now()).count() << " seconds" << std::endl;
            return token.value;
        }
    }

    httplib::Client cli("https://api-m.sandbox.paypal.com");
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(10, 0);
    cli.set_basic_auth(get_env_or_empty("PAYPAL_CLIENT_ID"), get_env_or_empty("PAYPAL_CLIENT_SECRET"));

    auto res = cli.Post("/v1/oauth2/token", "grant_type=client_credentials", "application/x-www-form-urlencoded");

    if(!res)
    {
        std::cerr << "Token request failed: " << httplib::to_string(res.error()) << std::endl;
        return "";
    }

    if(res->status != 200)
    {
        std::cerr << "Token request returned HTTP " << std::to_string(res->status) << std::endl;
        return "";
    }

    auto body = json::parse(res->body, nullptr, false);
    if(body.is_discarded())
    {
        std::cerr << "Token endpoint returned invalid JSON" << std::endl;
        return "";
    }

    const std::string temp_token_value = body.value("access_token", "");
    const int temp_expire_in = body.value("expires_in", 0);

    if(temp_token_value != "" && temp_expire_in > 0)
    {
        std::lock_guard lock(token.mtx);
        token.value = temp_token_value;
        token.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(temp_expire_in);
        std::cout << "New token generated and expires in " << temp_expire_in << " seconds" << std::endl;
        return token.value;
    }
    else
    {
        return "";
    }
}

VerifyResult verify_webhook(const httplib::Request& req) 
{
    const std::string paypal_transmission_id = req.get_header_value("PAYPAL-TRANSMISSION-ID");
    const std::string paypal_auth_algo = req.get_header_value("PAYPAL-AUTH-ALGO");
    const std::string paypal_cert_url = req.get_header_value("PAYPAL-CERT-URL");
    const std::string paypal_transmission_sig = req.get_header_value("PAYPAL-TRANSMISSION-SIG");
    const std::string paypal_transmission_time = req.get_header_value("PAYPAL-TRANSMISSION-TIME");

    const std::string paypal_webhook_id = get_env_or_empty("PAYPAL_WEBHOOK_ID");

    if(paypal_transmission_id == "")
    {
        std::cerr << "Paypal http request is missing PAYPAL-TRANSMISSION-ID.." << std::endl;
        return VerifyResult::RESULT_REJECTED;
    }

    if(paypal_auth_algo == "")
    {
        std::cerr << "Paypal http request is missing PAYPAL-AUTH-ALGO.." << std::endl;
        return VerifyResult::RESULT_REJECTED;
    }

    if(paypal_cert_url == "")
    {
        std::cerr << "Paypal http request is missing PAYPAL-CERT-URL.." << std::endl;
        return VerifyResult::RESULT_REJECTED;
    }

    if(paypal_transmission_sig == "")
    {
        std::cerr << "Paypal http request is missing PAYPAL-TRANSMISSION-SIG.." << std::endl;
        return VerifyResult::RESULT_REJECTED;
    }

    if(paypal_transmission_time == "")
    {
        std::cerr << "Paypal http request is missing PAYPAL-TRANSMISSION-TIME.." << std::endl;
        return VerifyResult::RESULT_REJECTED;
    }

    if(paypal_webhook_id == "")
    {
        std::cerr << "PAYPAL_WEBHOOK_ID is missing.." << std::endl;
        return VerifyResult::RESULT_ERROR;
    }

    std::ostringstream req_body;

    req_body << "{\"auth_algo\":" << json(paypal_auth_algo).dump()
     << ",\"cert_url\":" << json(paypal_cert_url).dump()
     << ",\"transmission_id\":" << json(paypal_transmission_id).dump()
     << ",\"transmission_sig\":" << json(paypal_transmission_sig).dump()
     << ",\"transmission_time\":" << json(paypal_transmission_time).dump()
     << ",\"webhook_id\":" << json(paypal_webhook_id).dump()
     << ",\"webhook_event\":" << req.body << "}";

    const std::string access_token = get_access_token();

     if(access_token == "")
     {
        return VerifyResult::RESULT_ERROR;
     }

    httplib::Client cli("https://api-m.sandbox.paypal.com");
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(10, 0);

    httplib::Headers headers = {{"Authorization", "Bearer " + access_token}};
    const auto res = cli.Post("/v1/notifications/verify-webhook-signature", headers, req_body.str(), "application/json");

    if(!res)
    {
        std::cerr << "Post request failed: " << httplib::to_string(res.error()) << std::endl;
        return VerifyResult::RESULT_ERROR;
    }

    if(res->status != 200)
    {
        std::cerr << "Post request returned HTTP " << std::to_string(res->status) << std::endl;
        return VerifyResult::RESULT_ERROR;
    }

    const auto body = json::parse(res->body, nullptr, false);
    if(body.is_discarded())
    {
        std::cerr << "Post endpoint returned invalid JSON" << std::endl;
        return VerifyResult::RESULT_ERROR;
    }

    const std::string verification_status = body.value("verification_status", "");
    
    if(verification_status.compare("SUCCESS") == 0)
    {
        return VerifyResult::RESULT_VERIFIED;
    }
    else if(verification_status.compare("FAILURE") == 0)
    {
        return VerifyResult::RESULT_REJECTED;
    }
    else
    {
        return VerifyResult::RESULT_ERROR;
    }
}

// TODO (agentic action): issue a sandbox refund for a capture id.
//       Decide: what does it return? How do you handle failure / retries?
bool refund_capture(const std::string& capture_id) 
{
    // TODO
    return false;
}

// ---------------------------------------------------------------------------
// 4. PARSING
// ---------------------------------------------------------------------------
std::optional<int64_t> parse_cents(const std::string& s)
{
    if(s.empty())
    {
        return std::nullopt;
    }

    std::string whole{}, fraction{};
    size_t decimal_point_pos = s.find('.');

    auto digit_check = [](char c) {
            return c >= '0' && c <= '9';
        };

    if(decimal_point_pos != std::string::npos)
    {
        whole = s.substr(0, decimal_point_pos);
        fraction = s.substr(decimal_point_pos + 1);

        if(whole.size() == 0 || fraction.size() == 0)
        {
            return std::nullopt;
        }

        if(!std::all_of(whole.begin(), whole.end(), digit_check) || !std::all_of(fraction.begin(), fraction.end(), digit_check))
        {
            return std::nullopt;
        }

        if(fraction.size() > 2 || whole.size() > 15)
        {
            return std::nullopt;
        }

        fraction.append(2 - fraction.size(), '0');
    }
    else
    {
        whole = s;

        if(!std::all_of(whole.begin(), whole.end(), digit_check))
        {
            return std::nullopt;
        }

        if(whole.size() > 15)
        {
            return std::nullopt;
        }
    }

    int64_t frac_value = 0, whole_value = 0;

    for(size_t i = 0; i < whole.size(); ++i)
    {
        whole_value = whole_value * 10 + (whole[i] - '0');
    }

    for(size_t i = 0; i < fraction.size(); ++i)
    {
        frac_value = frac_value * 10 + (fraction[i] - '0');
    }

    return whole_value * 100 + frac_value;
}

std::string now_iso8601_utc()
{
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    gmtime_r(&time, &tm);

    char buf[32];
    if(std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
    {
        return "";
    }

    return std::string(buf);
}

std::optional<TxnRecord> parse_event(const json& body) 
{
    static TxnRecord txn;
    static std::unordered_set<std::string> event_types{"PAYMENT.CAPTURE.COMPLETED", "PAYMENT.CAPTURE.DENIED"};

    try
    {

        txn.event_type = body.value("event_type", "");

        if(event_types.find(txn.event_type) == event_types.end())
        {
            return std::nullopt;
        }

        if(!(body.contains("resource") && body["resource"].is_object()))
        {
            return std::nullopt;
        }

        const auto& res = body["resource"];
        txn.event_id = body.value("id", "");
        txn.capture_id = res.value("capture_id", "");
        txn.status = res.value("status", "");
        txn.create_time = res.value("create_time", "");
        txn.order_id = body.value(json::json_pointer("/resource/supplementary_data/related_ids/order_id"), std::string{});

        if(!(res.contains("amount") && res["amount"].is_object()) || txn.event_id.empty() || txn.capture_id.empty())
        {
            return std::nullopt;
        }

        const auto& amount_data = res["amount"];

        const std::string value = amount_data.value("value ","");
        const std::string currency_code = amount_data.value("currency_code ","");

        const std::optional<int64_t> amount_cents = parse_cents(value);

        if(amount_cents == std::nullopt || currency_code != "USD") //Only handle USD for now as other currencies have different minor units
        {          
            return std::nullopt;
        }

        txn.amount_cents = *amount_cents;
        txn.received_at = now_iso8601_utc();
        return txn;
    }
    catch(const json::exception&)
    {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// 5. RISK SCORING (the fast C++ path)
// TODO: rules such as amount outlier vs rolling baseline, velocity per payer,
//       country mismatch, negative events (denied / reversed / dispute).
// TODO: what state do rules need? (per-payer history, rolling stats)
// TODO: keep it allocation-light; you'll benchmark this later.
// ---------------------------------------------------------------------------
void score(TxnRecord& t) 
{
    // TODO
}

// ---------------------------------------------------------------------------
// 6. LLM TRIAGE (the AI layer, off the hot path)
// TODO: choose a provider and design the prompt: what context do you send,
//       what structured output do you require (e.g. JSON: decision + reason)?
// TODO: only call this for transactions above a risk threshold.
// TODO: run it asynchronously (worker thread + queue) so webhooks ack fast.
// TODO: handle timeouts, malformed model output, and API errors.
// ---------------------------------------------------------------------------
struct Triage 
{
    // TODO: e.g. decision (approve / hold / refund), explanation
};

Triage ask_llm(const TxnRecord& t) 
{
    // TODO
    return {};
}

// ---------------------------------------------------------------------------
// 7. POLICY / ACTION
// TODO: map triage + risk score to an action. Decide guardrails: when must a
//       human approve instead of the agent acting automatically?
// ---------------------------------------------------------------------------
void act_on(TxnRecord& t, const Triage& tr) 
{
    // TODO
}

// ---------------------------------------------------------------------------
// 8. HTTP SERVER
// ---------------------------------------------------------------------------
int main() 
{
    if(get_env_or_empty("PAYPAL_CLIENT_ID") == "")
    {
        std::cerr << "Missing PAYPAL_CLIENT_ID.." << std::endl;
        return 1;
    } 

    if(get_env_or_empty("PAYPAL_CLIENT_SECRET") == "")
    {
        std::cerr << "Missing PAYPAL_CLIENT_SECRET.." << std::endl;
        return 1;
    } 

    httplib::Server svr;

    svr.Get("/health", [](const httplib::Request &, httplib::Response &res) 
    {
        res.set_content("ok", "text/plain");
        res.status = 200;
    });

    //   verify -> parse -> score -> store -> enqueue for triage -> ack quickly
    svr.Post("/webhook", [](const httplib::Request &req, httplib::Response &res) 
    {
        VerifyResult result = verify_webhook(req);
        if(result == VerifyResult::RESULT_VERIFIED)
        {
            auto body = json::parse(req.body, nullptr, false);

            if(body.is_discarded())
            {
                std::cerr << "Webhook body is not valid JSON" << std::endl;
                res.status = 401;
                res.set_content("Webhook body is not valid JSON", "text/plain");
                return;
            }

            auto rec = parse_event(body);
            if(!rec)
            {
                std::cerr << "Webhook body is not a valid event " << body.value("event_type", "") << std::endl;
                res.status = 401;
                res.set_content("Webhook body is not a valid event " + body.value("event_type", ""), "text/plain");
                return;
            }

            std::cout  << "Received event: " << rec->event_type << ", eventID: " << rec->event_id 
            << ", capture_id: " << rec->capture_id << ", order_id: " << rec->order_id << ", currency: " << rec->currency 
            << ", amount_cents: " << rec->amount_cents << ", status: " << rec->status << ", received at: " << rec->received_at << std::endl;

            res.status = 200;
            res.set_content("ok", "text/plain");
        }
        else if(result == VerifyResult::RESULT_REJECTED)
        {
            res.status = 401;
            res.set_content("error", "text/plain");
        }  
        else
        {
            res.status = 503;
            res.set_content("error", "text/plain");
        }  
         
            std::cout << "\nBody: " << req.body << std::endl;
            std::cout << "Header PAYPAL-TRANSMISSION-ID: " << req.get_header_value("PAYPAL-TRANSMISSION-ID") << std::endl;
            std::cout << "Header PAYPAL-AUTH-ALGO: " << req.get_header_value("PAYPAL-AUTH-ALGO") << std::endl;
            std::cout << "Header PAYPAL-CERT-URL: " << req.get_header_value("PAYPAL-CERT-URL") << std::endl;
            std::cout << "Header PAYPAL-TRANSMISSION-SIG: " << req.get_header_value("PAYPAL-TRANSMISSION-SIG") << std::endl;
            std::cout << "Header PAYPAL-TRANSMISSION-TIME: " << req.get_header_value("PAYPAL-TRANSMISSION-TIME") << std::endl << std::endl;

    });

    // TODO: GET /api/txns   (data for the dashboard)

    // TODO: GET /            (dashboard: table of transactions, risk, AI reasoning, action)

    // TODO: start worker thread(s) for LLM triage; shut down cleanly

    if(get_access_token() != "")
    {
        std::cout << "Access Token retrieved!" << std::endl;
    }
    else
    {
        std::cerr << "Access token failed to be retrieved.." << std::endl;
    }

    if(!svr.listen("0.0.0.0", 8080))
    {
        std::cout << "Failed to listen to port" << std::endl;
    }
}

// ---------------------------------------------------------------------------
// 9. BENCHMARK (do this last, it's your C++ selling point)
// TODO: separate executable or mode that replays N synthetic events through
//       parse + score and reports events/sec and p50 / p99 / p99.9 latency.
// ---------------------------------------------------------------------------
