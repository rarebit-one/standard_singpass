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
    expect { run_generator }.to output(/create.+standard_singpass\.rb/).to_stdout

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

    expect { run_generator }.to output(/identical.+standard_singpass\.rb/).to_stdout

    expect(File.read(initializer_path)).to eq("# user edits\n")
    expect(original).not_to eq("# user edits\n")
  end

  it "overwrites with --force" do
    run_generator
    File.write(initializer_path, "# user edits\n")

    expect { run_generator(["--force"]) }.to output(/force.+standard_singpass\.rb/).to_stdout

    expect(File.read(initializer_path)).to include("StandardSingpass::Myinfo.configure")
  end
end
