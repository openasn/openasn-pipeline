# frozen_string_literal: true

# Which exports this build produces, and which it is REQUIRED to produce
# (PRD §17.4).
#
# Two values, from two different places on purpose:
#
#   OPENASN_EXPORTS=none|portable|all   what this run selects
#   export-contract.json required_mode  what a published release must carry
#
# The required mode is owned by the DATA repo, not by this code, because it
# is a promise to consumers: once a release ships openasn.sqlite.gz, a later
# release that quietly omits it breaks every pinned updater. A constant in
# the pipeline could be forgotten by a scheduled run; a tracked file in the
# repository that publishes the data cannot, and it lands through the same
# reviewed PR that installs the toolchain the assets need.
#
# The failure modes are deliberately asymmetric. A PRE-FEATURE checkout with
# no export-contract.json at all defaults to `none`, because that is exactly
# what an old dataset revision means. Anything else - a malformed file, an
# unknown mode, a config_version this producer does not understand, an
# identity that disagrees with the schema/profile these writers emit - is a
# hard failure. A silent fallback to `none` is how a release loses its
# exports without anyone noticing, so there is exactly one path to `none`
# and it requires the file to be absent.
#
# Local non-publishing runs may select any mode, higher or lower than
# required, for debugging. A PUBLISHING run may not select below required.

require "json"
require_relative "../lib/env"
require_relative "contract"

module OpenASNPipeline
  module Export
    module Mode
      ORDER = Contract::EXPORT_MODES
      CONFIG_NAME = "export-contract.json"
      CONFIG_VERSION = 1
      ENV_NAME = "OPENASN_EXPORTS"

      # The identities the config declares must be the identities these
      # writers actually stamp into every asset. Checked for equality, never
      # for compatibility: a producer that would emit anything else has to
      # fail rather than publish a mislabeled file.
      IDENTITIES = {
        "schema_version" => Contract::SCHEMA_VERSION,
        "schema_revision" => Contract::SCHEMA_REVISION,
        "classification_profile" => Contract::CLASSIFICATION_PROFILE,
        "lookup_policy_version" => Contract::LOOKUP_POLICY_VERSION
      }.freeze

      Resolved = Struct.new(:selected, :required, :config_path, :assets, keyword_init: true) do
        def exports? = selected != "none"
        def rank = ORDER.index(selected)
        def to_s = "#{selected} (required: #{required})"
      end

      module_function

      # config_path is injectable so the offline unit tests can resolve a
      # fixture config without a data-repo checkout.
      def resolve(selected: ENV[ENV_NAME], config_path: nil, data_repo: nil, publishing: ENV["PUBLISH"] == "1")
        path = config_path || File.join(data_repo || Env.data_repo, CONFIG_NAME)
        config = load_config(path)
        required = config.fetch("required_mode")

        chosen = normalize_selected(selected, required)
        if publishing && ORDER.index(chosen) < ORDER.index(required)
          Env.fail_stage!("#{ENV_NAME}=#{chosen} but #{File.basename(path)} requires #{required} for a " \
                          "published release. Every release from the #{required} activation on must carry " \
                          "its assets; lowering the mode to make a build green would break every consumer " \
                          "pinned to the format.")
        end

        assets = config.fetch("assets").fetch(chosen)
        Env.log("exports: mode #{chosen} (required #{required}, from #{path})" \
                "#{assets.empty? ? '' : " -> #{assets.join(', ')}"}")
        Resolved.new(selected: chosen, required: required, config_path: path, assets: assets)
      end

      def normalize_selected(selected, required)
        value = selected.to_s.strip
        return required if value.empty?
        return value if ORDER.include?(value)

        Env.fail_stage!("#{ENV_NAME}=#{value.inspect} is not one of #{ORDER.join('/')}")
      end

      # The ONLY route to a defaulted `none`: the file is absent, which is
      # what a dataset checkout from before this feature looks like.
      def load_config(path)
        unless File.file?(path)
          Env.warn("exports: #{path} does not exist, so this dataset revision predates the export contract " \
                   "and requires no exports (mode none). A malformed contract would NOT default this way.")
          return { "required_mode" => "none", "assets" => ORDER.to_h { |m| [m, []] } }
        end

        config = begin
          JSON.parse(File.read(path))
        rescue JSON::ParserError => e
          Env.fail_stage!("#{path} is not valid JSON (#{e.message}). A malformed export contract is a hard " \
                          "failure, never a silent fallback to no exports.")
        end
        validate!(config, path)
        config
      end

      def validate!(config, path)
        unless config.is_a?(Hash)
          Env.fail_stage!("#{path} is #{config.class}, expected a JSON object")
        end
        unless config["config_version"] == CONFIG_VERSION
          Env.fail_stage!("#{path} has config_version #{config['config_version'].inspect}; this producer " \
                          "understands #{CONFIG_VERSION} and will not guess at another shape")
        end

        required = config["required_mode"]
        unless ORDER.include?(required)
          Env.fail_stage!("#{path} requires mode #{required.inspect}, which is not one of #{ORDER.join('/')}")
        end

        IDENTITIES.each do |key, expected|
          next if config[key] == expected

          Env.fail_stage!("#{path} declares #{key}=#{config[key].inspect} but these writers emit " \
                          "#{expected.inspect}. Publishing under a label the bytes do not carry is worse " \
                          "than not publishing.")
        end

        assets = config["assets"]
        unless assets.is_a?(Hash) && ORDER.all? { |mode| assets[mode].is_a?(Array) }
          Env.fail_stage!("#{path} must list the assets of every mode (#{ORDER.join(', ')})")
        end
        config
      end
    end
  end
end
