# typed: ignore

require "rails_helper"
require "generators/standard_singpass/install/install_generator"

RSpec.describe StandardSingpass::Generators::InstallGenerator, type: :generator do
  let(:destination) { File.expand_path("../../../tmp/generator", __dir__) }
  let(:initializer_path) { File.join(destination, "config/initializers/standard_singpass.rb") }

  before do
    FileUtils.rm_rf(destination)
    FileUtils.mkdir_p(destination)
  end

  after do
    FileUtils.rm_rf(destination)
  end

  def run_generator(args = [])
    described_class.start(args, destination_root: destination)
  end

  it "writes the initializer" do
    run_generator
    expect(File).to exist(initializer_path)
    content = File.read(initializer_path)
    expect(content).to include("StandardSingpass::Myinfo.configure")
    expect(content).to include("c.client_id    = ENV[\"MYINFO_CLIENT_ID\"]")
    expect(content).to include("c.private_jwks_json")
  end

  it "is idempotent — skips when initializer already exists" do
    run_generator
    original = File.read(initializer_path)
    File.write(initializer_path, "# user edits\n")

    capture(:stdout) { run_generator }

    expect(File.read(initializer_path)).to eq("# user edits\n")
    expect(original).not_to eq("# user edits\n")
  end

  it "overwrites with --force" do
    run_generator
    File.write(initializer_path, "# user edits\n")

    capture(:stdout) { run_generator(["--force"]) }

    expect(File.read(initializer_path)).to include("StandardSingpass::Myinfo.configure")
  end

  def capture(stream)
    stream = stream.to_s
    captured = ""
    original_stream = $stdout if stream == "stdout"
    original_stream = $stderr if stream == "stderr"
    $stdout = StringIO.new if stream == "stdout"
    $stderr = StringIO.new if stream == "stderr"
    yield
    captured = $stdout.string if stream == "stdout"
    captured = $stderr.string if stream == "stderr"
    captured
  ensure
    $stdout = original_stream if stream == "stdout"
    $stderr = original_stream if stream == "stderr"
  end
end
