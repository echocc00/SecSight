"""drop case approvals column (双真相源清理)

审批数据唯一真相源是 approval_records 表。cases.approvals JSON 列从未被
审批服务写入,checkpointer 路径误读它导致已签批动作被判 pending 不执行。

Revision ID: b3f7a1c4d2e9
Revises: a8d482b9ceac
Create Date: 2026-10-25

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3f7a1c4d2e9'
down_revision: Union[str, None] = 'a8d482b9ceac'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table: SQLite 不支持直接 DROP COLUMN,batch 模式用重建表实现
    with op.batch_alter_table('cases', schema=None) as batch_op:
        batch_op.drop_column('approvals')


def downgrade() -> None:
    with op.batch_alter_table('cases', schema=None) as batch_op:
        batch_op.add_column(sa.Column('approvals', sa.JSON(), nullable=True))
