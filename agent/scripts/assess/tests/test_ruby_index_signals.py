"""Ruby route and controller signals used to direct code review."""

from __future__ import annotations

import pytest

from assess.lib.treesitter_index import index_file


def test_sinatra_route_block_exposes_entry_and_nested_sink() -> None:
    source = b"""\
get '/files/:name' do
  File.read(params[:name])
end
"""

    indexed = index_file("app.rb", "ruby", source)

    assert indexed["analysis_status"] == "complete"
    assert any(item["kind"] == "sinatra_route" and item["line"] == 1
               for item in indexed["entry_points"])
    assert any(item["kind"] == "file_path" and item["line"] == 2
               for item in indexed["security_sinks"])


@pytest.mark.parametrize("verb", ["patch", "options", "head"])
def test_other_sinatra_http_verbs_expose_route_blocks(verb: str) -> None:
    source = f"{verb} '/files/:name' do\n  File.read(params[:name])\nend\n".encode()

    indexed = index_file("app.rb", "ruby", source)

    assert any(item["kind"] == "sinatra_route" and item["line"] == 1
               for item in indexed["entry_points"])
    assert any(item["kind"] == "file_path" and item["line"] == 2
               for item in indexed["security_sinks"])


def test_rails_routes_draw_exposes_route_registration() -> None:
    source = b"""\
Rails.application.routes.draw do
  get 'files/:name', to: 'files#show'
end
"""

    indexed = index_file("config/routes.rb", "ruby", source)

    assert any(item["kind"] == "rails_route" for item in indexed["entry_points"])


def test_rails_controller_public_action_is_candidate_entry() -> None:
    source = b"""\
class FilesController < ApplicationController
  def show
    File.read(params[:name])
  end
end
"""

    indexed = index_file("app/controllers/files_controller.rb", "ruby", source)

    assert indexed["analysis_status"] == "complete"
    assert any(item["name"] == "show" and item["kind"] == "rails_action"
               for item in indexed["entry_points"])


def test_private_rails_controller_method_is_not_action() -> None:
    source = b"""\
class FilesController < ApplicationController
  def show
    params[:name]
  end

  private

  def helper
    params[:name]
  end
end
"""

    indexed = index_file("app/controllers/files_controller.rb", "ruby", source)

    assert any(item["name"] == "show" for item in indexed["entry_points"])
    assert not any(item["name"] == "helper" for item in indexed["entry_points"])


def test_hash_delete_is_not_sinatra_route() -> None:
    source = b"""\
class Cache
  def cleanup(params)
    params.delete 'confirm'
  end
end
"""

    indexed = index_file("cache.rb", "ruby", source)

    assert indexed["analysis_status"] == "complete"
    assert not indexed["entry_points"]
