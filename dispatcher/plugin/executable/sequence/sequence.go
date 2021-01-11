//     Copyright (C) 2020-2021, IrineSistiana
//
//     This file is part of mosdns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package sequence

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/dispatcher/handler"
)

const PluginType = "sequence"

func init() {
	handler.RegInitFunc(PluginType, Init, func() interface{} { return new(Args) })

	handler.MustRegPlugin(&noop{BP: handler.NewBP("_end", PluginType)}, true)
}

var _ handler.ExecutablePlugin = (*sequenceRouter)(nil)

type sequenceRouter struct {
	*handler.BP

	ecs *handler.ExecutableCmdSequence
}

type noop struct {
	*handler.BP
}

func (n *noop) Exec(_ context.Context, _ *handler.Context) (_ error) { return nil }

type Args struct {
	Exec []interface{} `yaml:"exec"`
}

func Init(bp *handler.BP, args interface{}) (p handler.Plugin, err error) {
	return newSequencePlugin(bp, args.(*Args))
}

func newSequencePlugin(bp *handler.BP, args *Args) (*sequenceRouter, error) {
	ecs, err := handler.ParseExecutableCmdSequence(args.Exec)
	if err != nil {
		return nil, fmt.Errorf("invalid exec squence: %w", err)
	}

	return &sequenceRouter{
		BP:  bp,
		ecs: ecs,
	}, nil
}

func (s *sequenceRouter) Exec(ctx context.Context, qCtx *handler.Context) (err error) {
	return handler.WalkExecutableCmd(ctx, qCtx, s.L(), s.ecs)
}