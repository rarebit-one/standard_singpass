# typed: false

require "rails_helper"

RSpec.describe StandardSingpass::Myinfo::FailureClassifier do
  describe "::UPSTREAM_UNAVAILABLE_STATUSES" do
    it "is the documented Singpass upstream-outage status set" do
      expect(described_class::UPSTREAM_UNAVAILABLE_STATUSES).to eq([502, 503, 504])
    end

    it "is the same list the client retries on, so the two cannot drift" do
      expect(StandardSingpass::Myinfo::Client::RETRYABLE_USERINFO_STATUSES)
        .to be(described_class::UPSTREAM_UNAVAILABLE_STATUSES)
    end
  end

  describe ".upstream_unavailable?" do
    context "with an ApiError carrying a status" do
      [502, 503, 504].each do |status|
        it "is true for #{status}" do
          error = StandardSingpass::Myinfo::ApiError.new("boom", status: status)

          expect(described_class.upstream_unavailable?(error)).to be(true)
        end
      end

      [400, 401, 403, 404, 422, 500].each do |status|
        it "is false for #{status} — our request, not their availability" do
          error = StandardSingpass::Myinfo::ApiError.new("boom", status: status)

          expect(described_class.upstream_unavailable?(error)).to be(false)
        end
      end
    end

    it "is true for a rate-limit error — transient, same advice to the user" do
      error = StandardSingpass::Myinfo::RateLimitError.new("slow down")

      expect(described_class.upstream_unavailable?(error)).to be(true)
    end

    it "is true for a transport failure on the token/userinfo leg" do
      error = StandardSingpass::Myinfo::ApiError.new(
        "MyInfo userinfo endpoint unreachable: Faraday::ConnectionFailed",
        transport: true
      )

      expect(error.status).to be_nil
      expect(described_class.upstream_unavailable?(error)).to be(true)
    end

    context "with a PARError carrying a status" do
      # The PAR leg raises its own class, so classifying only ApiError would
      # report a PAR-side outage as our own bug.
      [502, 503, 504].each do |status|
        it "is true for a PAR-leg #{status}" do
          error = StandardSingpass::Myinfo::PARError.new("PAR failed", status: status)

          expect(described_class.upstream_unavailable?(error)).to be(true)
        end
      end

      it "is false for a PAR-leg 400 — our request was malformed" do
        error = StandardSingpass::Myinfo::PARError.new("PAR failed", status: 400)

        expect(described_class.upstream_unavailable?(error)).to be(false)
      end

      it "is false for a statusless PARError (bad response shape, not an outage)" do
        error = StandardSingpass::Myinfo::PARError.new("PAR response missing required fields")

        expect(described_class.upstream_unavailable?(error)).to be(false)
      end
    end

    it "is true for a transport failure on the PAR leg" do
      error = StandardSingpass::Myinfo::PARError.new(
        "PAR endpoint unreachable: Faraday::ConnectionFailed",
        transport: true
      )

      expect(described_class.upstream_unavailable?(error)).to be(true)
    end

    it "is false for a statusless ApiError a host raised itself" do
      error = StandardSingpass::Myinfo::ApiError.new("no person data in response")

      expect(described_class.upstream_unavailable?(error)).to be(false)
    end

    it "does not classify from the message text" do
      # Same wording as a real transport failure, but without the flag. The
      # message is not an interface; only the structured flag counts.
      error = StandardSingpass::Myinfo::ApiError.new("endpoint unreachable: Faraday::ConnectionFailed")

      expect(described_class.upstream_unavailable?(error)).to be(false)
    end

    [
      StandardSingpass::Myinfo::AuthenticationError,
      StandardSingpass::Myinfo::DecryptionError,
      StandardSingpass::Myinfo::SignatureError,
      StandardSingpass::Myinfo::ConfigurationError
    ].each do |klass|
      it "is false for #{klass} — our side is wrong, retrying will not help" do
        expect(described_class.upstream_unavailable?(klass.new("boom"))).to be(false)
      end
    end

    it "is false for an exception from outside the gem" do
      expect(described_class.upstream_unavailable?(ArgumentError.new("boom"))).to be(false)
    end
  end
end
